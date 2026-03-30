const express    = require('express');
const multer     = require('multer');
const cors       = require('cors');
const { exec }   = require('child_process');
const fs         = require('fs');
const path       = require('path');
const os         = require('os');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS ──
// Allow requests from your site
app.use(cors({
  origin: [
    'https://sipsymposium.com',
    'https://www.sipsymposium.com',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));

app.use(express.json());

// ── API key protection ──
// Set PCAP_API_KEY env var in Railway to protect this endpoint
function checkApiKey(req, res, next) {
  const key = process.env.PCAP_API_KEY;
  if (!key) return next(); // No key set = open (dev mode)
  const provided = req.headers['x-api-key'];
  if (!provided || provided !== key) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Multer — store upload in temp dir ──
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
  fileFilter: function(req, file, cb) {
    const allowed = ['.pcap', '.pcapng', '.cap'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext) || file.mimetype === 'application/octet-stream') {
      cb(null, true);
    } else {
      cb(new Error('Only .pcap, .pcapng, and .cap files are supported'));
    }
  }
});

// ── Helper: run a shell command as a Promise ──
function run(cmd, timeout) {
  timeout = timeout || 30000;
  return new Promise(function(resolve, reject) {
    exec(cmd, { maxBuffer: 20 * 1024 * 1024, timeout: timeout }, function(err, stdout, stderr) {
      if (err && !stdout) {
        reject(new Error(stderr || err.message));
      } else {
        resolve(stdout.trim());
      }
    });
  });
}

// ── Helper: safe JSON parse ──
function safeJSON(str) {
  try { return JSON.parse(str); } catch(e) { return null; }
}

// ── Helper: parse tshark -T fields output into array of objects ──
function parseFields(output, fieldNames) {
  if (!output) return [];
  return output.split('\n')
    .filter(function(l) { return l.trim(); })
    .map(function(line) {
      const parts = line.split('\t');
      const obj = {};
      fieldNames.forEach(function(f, i) {
        obj[f] = parts[i] ? parts[i].trim() : '';
      });
      return obj;
    });
}

// ── Helper: estimate MOS from packet loss and jitter ──
function estimateMOS(lossPercent, jitterMs) {
  // Based on E-model approximation
  const R = 93.2
    - (lossPercent * 2.5)
    - (jitterMs > 177.3 ? 0 : 0)
    - (Math.max(0, jitterMs - 177.3) * 0.1);
  const Rclamp = Math.max(0, Math.min(100, R));
  if (Rclamp < 0)  return 1.0;
  if (Rclamp > 100) return 4.5;
  const mos = 1 + 0.035 * Rclamp + Rclamp * (Rclamp - 60) * (100 - Rclamp) * 7e-6;
  return Math.round(Math.min(4.5, Math.max(1.0, mos)) * 100) / 100;
}

// ── Main PCAP analysis function ──
async function analyzePcap(filePath) {
  const result = {
    summary:     {},
    sip:         { messages: [], dialogs: [], statistics: {} },
    sdp:         { offers: [], answers: [] },
    rtp:         { streams: [] },
    rtcp:        { reports: [] },
    dtmf:        { events: [] },
    dns:         { queries: [] },
    tls:         { sessions: [] },
    errors:      [],
    raw_stats:   {}
  };

  // ── 1. Capture summary ──
  try {
    const capInfo = await run(`tshark -r "${filePath}" -q -z io,stat,0 2>&1 | head -20`);
    const countOut = await run(`tshark -r "${filePath}" 2>/dev/null | wc -l`);
    result.summary.total_packets = parseInt(countOut) || 0;

    // Duration and byte count
    const durOut = await run(
      `tshark -r "${filePath}" -T fields -e frame.time_relative 2>/dev/null | tail -1`
    );
    result.summary.duration_seconds = parseFloat(durOut) || 0;

    const bytesOut = await run(
      `tshark -r "${filePath}" -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END {print s}'`
    );
    result.summary.total_bytes = parseInt(bytesOut) || 0;
  } catch(e) {
    result.errors.push('Summary: ' + e.message);
  }

  // ── 2. Protocol hierarchy ──
  try {
    const proto = await run(`tshark -r "${filePath}" -q -z io,phs 2>/dev/null`);
    result.summary.protocol_hierarchy = proto;
  } catch(e) {}

  // ── 3. SIP messages — full decode ──
  try {
    const sipOut = await run(
      `tshark -r "${filePath}" -Y sip -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e udp.srcport \
        -e udp.dstport \
        -e tcp.srcport \
        -e tcp.dstport \
        -e sip.Request-Line \
        -e sip.Status-Line \
        -e sip.msg_hdr \
        -e sip.Call-ID \
        -e sip.CSeq \
        -e sip.From \
        -e sip.To \
        -e sip.Via \
        -e sip.Contact \
        -e sip.User-Agent \
        -e sip.content-type \
        -e sip.Response-Code \
        -E separator="|" 2>/dev/null`
    );

    if (sipOut) {
      const lines = sipOut.split('\n').filter(function(l) { return l.trim(); });
      lines.forEach(function(line) {
        const p = line.split('|');
        const srcPort = p[4] || p[6] || '';
        const dstPort = p[5] || p[7] || '';
        const msg = {
          frame:         p[0],
          time:          p[1],
          src_ip:        p[2],
          dst_ip:        p[3],
          src_port:      srcPort,
          dst_port:      dstPort,
          request_line:  p[8],
          status_line:   p[9],
          headers:       p[10],
          call_id:       p[11],
          cseq:          p[12],
          from:          p[13],
          to:            p[14],
          via:           p[15],
          contact:       p[16],
          user_agent:    p[17],
          content_type:  p[18],
          response_code: p[19]
        };
        result.sip.messages.push(msg);
      });
      result.sip.statistics.total_messages = result.sip.messages.length;
    }
  } catch(e) {
    result.errors.push('SIP: ' + e.message);
  }

  // ── 4. SIP dialog analysis ──
  try {
    const dialogOut = await run(
      `tshark -r "${filePath}" -q -z sip,stat 2>/dev/null`
    );
    result.sip.statistics.dialog_stats = dialogOut;
  } catch(e) {}

  // ── 5. SDP extraction ──
  try {
    const sdpOut = await run(
      `tshark -r "${filePath}" -Y sip -T fields \
        -e sip.Call-ID \
        -e sip.Request-Line \
        -e sip.Status-Line \
        -e sdp.version \
        -e sdp.owner \
        -e sdp.connection_info \
        -e sdp.media \
        -e sdp.media_attr \
        -e sdp.time \
        -e sdp.bandwidth \
        -E separator="|" 2>/dev/null`
    );

    if (sdpOut) {
      const lines = sdpOut.split('\n').filter(function(l) { return l.trim() && l.includes('|'); });
      lines.forEach(function(line) {
        const p = line.split('|');
        if (p[3] || p[6]) { // has SDP content
          const sdpEntry = {
            call_id:         p[0],
            request_line:    p[1],
            status_line:     p[2],
            sdp_version:     p[3],
            owner:           p[4],
            connection:      p[5],
            media_lines:     p[6] ? p[6].split(',') : [],
            media_attrs:     p[7] ? p[7].split(',') : [],
            timing:          p[8],
            bandwidth:       p[9]
          };
          const isAnswer = p[2] && p[2].includes('200');
          if (isAnswer) {
            result.sdp.answers.push(sdpEntry);
          } else {
            result.sdp.offers.push(sdpEntry);
          }
        }
      });
    }
  } catch(e) {
    result.errors.push('SDP: ' + e.message);
  }

  // ── 6. RTP stream analysis ──
  try {
    // Get all RTP streams with full stats
    const rtpStreams = await run(
      `tshark -r "${filePath}" -q -z rtp,streams 2>/dev/null`
    );
    result.rtp.stream_summary = rtpStreams;

    // Detailed RTP fields per packet (sampled — first 5000 packets)
    const rtpFields = await run(
      `tshark -r "${filePath}" -Y rtp -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e udp.srcport \
        -e udp.dstport \
        -e rtp.ssrc \
        -e rtp.seq \
        -e rtp.timestamp \
        -e rtp.p_type \
        -e rtp.marker \
        -e rtp.ext \
        -e frame.len \
        -E separator="|" 2>/dev/null | head -5000`
    );

    if (rtpFields) {
      // Group by SSRC+flow
      const streamMap = {};
      rtpFields.split('\n').filter(function(l) { return l.trim(); }).forEach(function(line) {
        const p = line.split('|');
        const ssrc = p[6];
        const flow = (p[2] + ':' + p[4] + '->' + p[3] + ':' + p[5]);
        const key  = ssrc + '|' + flow;
        if (!streamMap[key]) {
          streamMap[key] = {
            ssrc:        ssrc,
            flow:        flow,
            src_ip:      p[2],
            dst_ip:      p[3],
            src_port:    p[4],
            dst_port:    p[5],
            payload_type: p[9],
            packets:     [],
            packet_count: 0,
            first_seq:   parseInt(p[7]) || 0,
            last_seq:    parseInt(p[7]) || 0,
            first_ts:    parseFloat(p[1]) || 0,
            last_ts:     parseFloat(p[1]) || 0,
            lost:        0,
            out_of_order: 0,
            marker_count: 0,
            total_bytes:  0
          };
        }
        const s   = streamMap[key];
        const seq = parseInt(p[7]) || 0;
        const ts  = parseFloat(p[1]) || 0;

        // Sequence gap detection
        if (s.packet_count > 0) {
          const expected = (s.last_seq + 1) % 65536;
          if (seq !== expected && seq !== s.last_seq) {
            const gap = (seq - s.last_seq - 1 + 65536) % 65536;
            if (gap > 0 && gap < 1000) s.lost += gap;
            if (seq < s.last_seq && gap > 32768) s.out_of_order++;
          }
        }

        if (p[10] === '1') s.marker_count++;
        s.last_seq  = seq;
        s.last_ts   = ts;
        s.total_bytes += parseInt(p[12]) || 0;
        s.packet_count++;
      });

      // Compute jitter and MOS for each stream
      Object.values(streamMap).forEach(function(s) {
        const duration = s.last_ts - s.first_ts;
        const lossRate = s.packet_count > 0 ? (s.lost / (s.packet_count + s.lost)) * 100 : 0;
        // Approximate jitter from timing variance (simplified)
        const avgPktRate = duration > 0 ? s.packet_count / duration : 0;
        const expectedInterval = avgPktRate > 0 ? 1000 / avgPktRate : 20;
        s.duration_seconds = Math.round(duration * 100) / 100;
        s.loss_percent     = Math.round(lossRate * 100) / 100;
        s.estimated_jitter_ms = Math.round(expectedInterval * 0.05 * 100) / 100; // rough estimate
        s.mos_estimate     = estimateMOS(lossRate, s.estimated_jitter_ms);
        s.bitrate_kbps     = duration > 0 ? Math.round((s.total_bytes * 8 / duration) / 1000) : 0;
        delete s.packets; // don't bloat response
        result.rtp.streams.push(s);
      });
    }
  } catch(e) {
    result.errors.push('RTP: ' + e.message);
  }

  // ── 7. RTCP reports ──
  try {
    const rtcpOut = await run(
      `tshark -r "${filePath}" -Y rtcp -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e rtcp.ssrc \
        -e rtcp.pt \
        -e rtcp.senderssrc \
        -e rtcp.ssrc.fraction \
        -e rtcp.ssrc.lost \
        -e rtcp.ssrc.ext_high_seq \
        -e rtcp.ssrc.jitter \
        -e rtcp.ssrc.lsr \
        -e rtcp.ssrc.dlsr \
        -e rtcp.sender.octet_count \
        -e rtcp.sender.packet_count \
        -E separator="|" 2>/dev/null`
    );
    if (rtcpOut) {
      rtcpOut.split('\n').filter(function(l) { return l.trim(); }).forEach(function(line) {
        const p = line.split('|');
        result.rtcp.reports.push({
          frame:          p[0],
          time:           p[1],
          src_ip:         p[2],
          dst_ip:         p[3],
          ssrc:           p[4],
          packet_type:    p[5],   // 200=SR, 201=RR, 202=SDES, 203=BYE
          sender_ssrc:    p[6],
          fraction_lost:  p[7],
          cumulative_lost: p[8],
          highest_seq:    p[9],
          jitter:         p[10],
          lsr:            p[11],
          dlsr:           p[12],
          octet_count:    p[13],
          packet_count:   p[14]
        });
      });
    }
  } catch(e) {
    result.errors.push('RTCP: ' + e.message);
  }

  // ── 8. DTMF events (RFC 2833 telephone-event) ──
  try {
    const dtmfOut = await run(
      `tshark -r "${filePath}" -Y "rtp.p_type==101 || rtp.p_type==96 || rtp.p_type==97" \
        -T fields \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e rtp.ssrc \
        -e rtp.p_type \
        -e rtp.telephone-event.event \
        -e rtp.telephone-event.duration \
        -e rtp.telephone-event.end \
        -E separator="|" 2>/dev/null`
    );
    if (dtmfOut) {
      dtmfOut.split('\n').filter(function(l) { return l.trim(); }).forEach(function(line) {
        const p = line.split('|');
        if (p[5]) {
          result.dtmf.events.push({
            time:      p[0],
            src_ip:    p[1],
            dst_ip:    p[2],
            ssrc:      p[3],
            pt:        p[4],
            digit:     p[5],
            duration:  p[6],
            end_bit:   p[7]
          });
        }
      });
    }
  } catch(e) {
    result.errors.push('DTMF: ' + e.message);
  }

  // ── 9. TLS/SRTP session info ──
  try {
    const tlsOut = await run(
      `tshark -r "${filePath}" -Y tls -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e tls.handshake.type \
        -e tls.handshake.version \
        -e tls.handshake.ciphersuite \
        -e tls.record.version \
        -e tls.handshake.extensions_server_name \
        -e tls.alert_message \
        -E separator="|" 2>/dev/null`
    );
    if (tlsOut) {
      tlsOut.split('\n').filter(function(l) { return l.trim(); }).forEach(function(line) {
        const p = line.split('|');
        result.tls.sessions.push({
          frame:       p[0],
          time:        p[1],
          src_ip:      p[2],
          dst_ip:      p[3],
          handshake_type: p[4],  // 1=ClientHello, 2=ServerHello, 11=Certificate, 14=ServerHelloDone
          version:     p[5],
          cipher_suite: p[6],
          record_version: p[7],
          sni:         p[8],
          alert:       p[9]
        });
      });
    }
  } catch(e) {
    result.errors.push('TLS: ' + e.message);
  }

  // ── 10. DNS queries ──
  try {
    const dnsOut = await run(
      `tshark -r "${filePath}" -Y dns -T fields \
        -e frame.time_relative \
        -e ip.src \
        -e dns.qry.name \
        -e dns.qry.type \
        -e dns.resp.name \
        -e dns.a \
        -e dns.flags.response \
        -E separator="|" 2>/dev/null | head -200`
    );
    if (dnsOut) {
      dnsOut.split('\n').filter(function(l) { return l.trim(); }).forEach(function(line) {
        const p = line.split('|');
        result.dns.queries.push({
          time:      p[0],
          src:       p[1],
          query:     p[2],
          type:      p[3],
          resp_name: p[4],
          answer_ip: p[5],
          is_response: p[6] === '1'
        });
      });
    }
  } catch(e) {
    result.errors.push('DNS: ' + e.message);
  }

  // ── 11. Expert info — tshark's own issue detection ──
  try {
    const expertOut = await run(
      `tshark -r "${filePath}" -q -z expert 2>/dev/null | head -100`
    );
    result.raw_stats.expert_info = expertOut;
  } catch(e) {}

  // ── 12. IO stats ──
  try {
    const ioOut = await run(
      `tshark -r "${filePath}" -q -z io,stat,1 2>/dev/null`
    );
    result.raw_stats.io_stats = ioOut;
  } catch(e) {}

  // ── 13. Conversation stats ──
  try {
    const convOut = await run(
      `tshark -r "${filePath}" -q -z conv,udp 2>/dev/null`
    );
    result.raw_stats.udp_conversations = convOut;

    const tcpConvOut = await run(
      `tshark -r "${filePath}" -q -z conv,tcp 2>/dev/null`
    );
    result.raw_stats.tcp_conversations = tcpConvOut;
  } catch(e) {}

  // ── Build formatted text for Claude ──
  result.formatted_for_ai = formatForClaude(result);

  return result;
}

// ── Format extracted data as clean text for Claude ──
function formatForClaude(data) {
  const lines = [];

  lines.push('=== PCAP ANALYSIS REPORT ===');
  lines.push('Total packets: ' + data.summary.total_packets);
  lines.push('Duration: ' + data.summary.duration_seconds + 's');
  lines.push('Total bytes: ' + data.summary.total_bytes);
  lines.push('');

  if (data.summary.protocol_hierarchy) {
    lines.push('=== PROTOCOL HIERARCHY ===');
    lines.push(data.summary.protocol_hierarchy);
    lines.push('');
  }

  // SIP
  if (data.sip.messages.length > 0) {
    lines.push('=== SIP MESSAGES (' + data.sip.messages.length + ') ===');
    data.sip.messages.forEach(function(m) {
      const method = m.request_line || m.status_line || 'UNKNOWN';
      const flow   = m.src_ip + ':' + m.src_port + ' -> ' + m.dst_ip + ':' + m.dst_port;
      lines.push('[' + m.time + 's] ' + method + ' | ' + flow);
      if (m.call_id)      lines.push('  Call-ID: '    + m.call_id);
      if (m.cseq)         lines.push('  CSeq: '       + m.cseq);
      if (m.from)         lines.push('  From: '       + m.from);
      if (m.to)           lines.push('  To: '         + m.to);
      if (m.via)          lines.push('  Via: '        + m.via);
      if (m.contact)      lines.push('  Contact: '    + m.contact);
      if (m.user_agent)   lines.push('  User-Agent: ' + m.user_agent);
      if (m.content_type) lines.push('  Content-Type: ' + m.content_type);
      lines.push('');
    });

    if (data.sip.statistics.dialog_stats) {
      lines.push('=== SIP DIALOG STATISTICS ===');
      lines.push(data.sip.statistics.dialog_stats);
      lines.push('');
    }
  }

  // SDP
  const allSdp = data.sdp.offers.concat(data.sdp.answers);
  if (allSdp.length > 0) {
    lines.push('=== SDP SESSIONS ===');
    allSdp.forEach(function(s) {
      lines.push('Call-ID: ' + s.call_id + ' | ' + (s.request_line || s.status_line));
      lines.push('  Connection: ' + s.connection);
      lines.push('  Owner: '     + s.owner);
      if (s.media_lines.length)  lines.push('  Media: '    + s.media_lines.join(' | '));
      if (s.media_attrs.length)  lines.push('  Attributes: ' + s.media_attrs.join(' | '));
      if (s.bandwidth)           lines.push('  Bandwidth: ' + s.bandwidth);
      lines.push('');
    });
  }

  // RTP
  if (data.rtp.streams.length > 0) {
    lines.push('=== RTP STREAMS ===');
    data.rtp.streams.forEach(function(s) {
      lines.push('Stream: ' + s.flow);
      lines.push('  SSRC: '           + s.ssrc);
      lines.push('  Payload type: '   + s.payload_type);
      lines.push('  Packets: '        + s.packet_count);
      lines.push('  Duration: '       + s.duration_seconds + 's');
      lines.push('  Packet loss: '    + s.loss_percent + '%');
      lines.push('  Est. jitter: '    + s.estimated_jitter_ms + 'ms');
      lines.push('  MOS estimate: '   + s.mos_estimate);
      lines.push('  Bitrate: '        + s.bitrate_kbps + ' kbps');
      lines.push('  Out of order: '   + s.out_of_order);
      lines.push('  Marker events: '  + s.marker_count);
      lines.push('');
    });

    if (data.rtp.stream_summary) {
      lines.push('=== RTP STREAM SUMMARY (tshark) ===');
      lines.push(data.rtp.stream_summary);
      lines.push('');
    }
  }

  // RTCP
  if (data.rtcp.reports.length > 0) {
    lines.push('=== RTCP REPORTS (' + data.rtcp.reports.length + ') ===');
    data.rtcp.reports.forEach(function(r) {
      const ptName = { '200':'SR', '201':'RR', '202':'SDES', '203':'BYE', '206':'PSFB', '205':'RTPFB' }[r.packet_type] || r.packet_type;
      lines.push('[' + r.time + 's] ' + ptName + ' | ' + r.src_ip + ' -> ' + r.dst_ip);
      if (r.ssrc)            lines.push('  SSRC: '            + r.ssrc);
      if (r.fraction_lost)   lines.push('  Fraction lost: '   + r.fraction_lost);
      if (r.cumulative_lost) lines.push('  Cumulative lost: ' + r.cumulative_lost);
      if (r.jitter)          lines.push('  Jitter: '          + r.jitter);
      if (r.packet_count)    lines.push('  Packets sent: '    + r.packet_count);
    });
    lines.push('');
  }

  // DTMF
  if (data.dtmf.events.length > 0) {
    lines.push('=== DTMF EVENTS ===');
    data.dtmf.events.forEach(function(d) {
      lines.push('[' + d.time + 's] Digit: ' + d.digit + ' | Duration: ' + d.duration + ' | ' + d.src_ip + ' -> ' + d.dst_ip);
    });
    lines.push('');
  }

  // TLS
  if (data.tls.sessions.length > 0) {
    lines.push('=== TLS/DTLS SESSIONS ===');
    const typeMap = { '1':'ClientHello', '2':'ServerHello', '11':'Certificate', '14':'ServerHelloDone', '20':'Finished', '22':'CertificateVerify' };
    data.tls.sessions.forEach(function(t) {
      const htype = typeMap[t.handshake_type] || ('type=' + t.handshake_type);
      lines.push('[' + t.time + 's] ' + htype + ' | ' + t.src_ip + ' -> ' + t.dst_ip);
      if (t.version)      lines.push('  Version: '      + t.version);
      if (t.cipher_suite) lines.push('  Cipher suite: ' + t.cipher_suite);
      if (t.sni)          lines.push('  SNI: '          + t.sni);
      if (t.alert)        lines.push('  ALERT: '        + t.alert);
    });
    lines.push('');
  }

  // DNS
  if (data.dns.queries.length > 0) {
    lines.push('=== DNS ===');
    data.dns.queries.slice(0, 30).forEach(function(d) {
      if (!d.is_response) {
        lines.push('[' + d.time + 's] Query: ' + d.query + ' (' + d.type + ')');
      } else if (d.answer_ip) {
        lines.push('[' + d.time + 's] Response: ' + d.query + ' -> ' + d.answer_ip);
      }
    });
    lines.push('');
  }

  // Expert info
  if (data.raw_stats.expert_info) {
    lines.push('=== TSHARK EXPERT INFO ===');
    lines.push(data.raw_stats.expert_info);
    lines.push('');
  }

  // Conversations
  if (data.raw_stats.udp_conversations) {
    lines.push('=== UDP CONVERSATIONS ===');
    lines.push(data.raw_stats.udp_conversations);
    lines.push('');
  }

  return lines.join('\n');
}

// ── Routes ──

// Health check
app.get('/', function(req, res) {
  res.json({
    status: 'ok',
    service: 'SIPSymposium PCAP Analyzer',
    version: '1.0.0'
  });
});

// Check tshark availability
app.get('/health', function(req, res) {
  exec('tshark --version 2>&1 | head -1', function(err, stdout) {
    res.json({
      status: err ? 'degraded' : 'ok',
      tshark: err ? 'not found' : stdout.trim(),
      uptime: process.uptime()
    });
  });
});

// Main PCAP analysis endpoint
app.post('/analyze', checkApiKey, upload.single('pcap'), async function(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded. Send a .pcap file as multipart/form-data with field name "pcap".' });
  }

  const filePath = req.file.path;
  console.log('[' + new Date().toISOString() + '] Analyzing: ' + req.file.originalname + ' (' + req.file.size + ' bytes)');

  try {
    const result = await analyzePcap(filePath);
    res.json({
      success: true,
      filename: req.file.originalname,
      file_size_bytes: req.file.size,
      analysis: result
    });
  } catch(e) {
    console.error('Analysis error:', e);
    res.status(500).json({ error: 'Analysis failed: ' + e.message });
  } finally {
    // Always clean up the temp file
    fs.unlink(filePath, function() {});
  }
});

// ── Start ──
app.listen(PORT, function() {
  console.log('SIPSymposium PCAP backend running on port ' + PORT);
  exec('tshark --version 2>&1 | head -1', function(err, stdout) {
    if (err) {
      console.warn('WARNING: tshark not found. Install with: apt-get install -y tshark');
    } else {
      console.log('tshark: ' + stdout.trim());
    }
  });
});
