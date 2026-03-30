const express    = require('express');
const multer     = require('multer');
const cors       = require('cors');
const { exec, execSync } = require('child_process');
const fs         = require('fs');
const path       = require('path');
const os         = require('os');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS ──
app.use(cors({
  origin: [
    'https://sipsymposium.com',
    'https://www.sipsymposium.com',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'http://127.0.0.1'
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));
app.use(express.json());

// ── API key protection ──
function checkApiKey(req, res, next) {
  const key = process.env.PCAP_API_KEY;
  if (!key) return next();
  const provided = req.headers['x-api-key'];
  if (!provided || provided !== key) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Multer ──
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB
  fileFilter: function(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.pcap','.pcapng','.cap'].includes(ext) || file.mimetype === 'application/octet-stream') {
      cb(null, true);
    } else {
      cb(new Error('Only .pcap, .pcapng, .cap files supported'));
    }
  }
});

// ── Run tshark command ──
function run(cmd, timeoutMs) {
  timeoutMs = timeoutMs || 60000;
  return new Promise(function(resolve, reject) {
    exec(cmd, { maxBuffer: 50 * 1024 * 1024, timeout: timeoutMs }, function(err, stdout, stderr) {
      if (err && !stdout) reject(new Error(stderr || err.message));
      else resolve((stdout || '').trim());
    });
  });
}

// ── MOS estimation (E-model) ──
function calcMOS(lossPercent, jitterMs, latencyMs) {
  latencyMs = latencyMs || 100;
  const Ie = lossPercent * 2.5;
  const Id = latencyMs > 177.3 ? 0.024 * latencyMs + 0.11 * (latencyMs - 177.3) : 0.024 * latencyMs;
  const R  = 93.2 - Ie - Id;
  const Rc = Math.max(0, Math.min(100, R));
  const mos = 1 + 0.035 * Rc + Rc * (Rc - 60) * (100 - Rc) * 7e-6;
  return Math.round(Math.min(4.5, Math.max(1.0, mos)) * 100) / 100;
}

// ── Codec name lookup ──
function codecName(pt) {
  const map = {
    '0':'G.711 PCMU','1':'1016','3':'GSM','4':'G.723','5':'DVI4-8k','6':'DVI4-16k',
    '7':'LPC','8':'G.711 PCMA','9':'G.722','10':'L16-2ch','11':'L16-1ch',
    '12':'QCELP','13':'CN','14':'MPA','15':'G.728','16':'DVI4-11k','17':'DVI4-22k',
    '18':'G.729','25':'CelB','26':'JPEG','28':'nv','31':'H.261','32':'MPV',
    '33':'MP2T','34':'H.263','96':'dynamic','97':'dynamic','98':'dynamic',
    '99':'dynamic','100':'dynamic','101':'telephone-event','102':'dynamic'
  };
  return map[pt] || ('PT=' + pt);
}

// ── RTCP packet type name ──
function rtcpTypeName(pt) {
  return { '200':'SR','201':'RR','202':'SDES','203':'BYE','204':'APP','205':'RTPFB','206':'PSFB' }[pt] || pt;
}

// ── Smart summarize SIP messages ──
function summarizeSIP(messages) {
  if (!messages.length) return { summary: 'No SIP traffic', dialogs: [], anomalies: [] };

  // Group by Call-ID
  const dialogs = {};
  messages.forEach(function(m) {
    const cid = m.call_id || 'unknown';
    if (!dialogs[cid]) {
      dialogs[cid] = {
        call_id: cid,
        messages: [],
        from: m.from,
        to: m.to,
        user_agents: new Set(),
        methods: [],
        responses: [],
        start_time: m.time,
        end_time: m.time,
        has_bye: false,
        has_cancel: false,
        has_auth: false,
        contact_ips: new Set(),
        via_ips: new Set()
      };
    }
    const d = dialogs[cid];
    d.messages.push(m);
    d.end_time = m.time;
    if (m.user_agent) d.user_agents.add(m.user_agent);
    if (m.request_line) {
      const method = m.request_line.split(' ')[0];
      if (!d.methods.includes(method)) d.methods.push(method);
      if (method === 'BYE')    d.has_bye    = true;
      if (method === 'CANCEL') d.has_cancel = true;
    }
    if (m.response_code) {
      if (!d.responses.includes(m.response_code)) d.responses.push(m.response_code);
      if (['401','407'].includes(m.response_code)) d.has_auth = true;
    }
    // Extract IPs from Contact and Via for NAT detection
    if (m.contact) {
      const ipMatch = m.contact.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
      if (ipMatch) ipMatch.forEach(function(ip) { d.contact_ips.add(ip); });
    }
    if (m.via) {
      const ipMatch = m.via.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
      if (ipMatch) ipMatch.forEach(function(ip) { d.via_ips.add(ip); });
    }
  });

  const anomalies = [];
  const dialogSummaries = Object.values(dialogs).map(function(d) {
    const duration = parseFloat(d.end_time) - parseFloat(d.start_time);
    const unanswered = !d.responses.some(function(r) { return r.startsWith('2'); });
    const retrans = d.messages.length > (d.methods.length + d.responses.length) * 2;

    // Detect anomalies
    if (unanswered && d.methods.includes('INVITE') && !d.has_cancel) {
      anomalies.push('Unanswered INVITE in dialog ' + d.call_id.substring(0,20));
    }
    if (retrans) {
      anomalies.push('Possible retransmissions in dialog ' + d.call_id.substring(0,20) + ' (' + d.messages.length + ' msgs, ' + d.methods.length + ' methods)');
    }
    if (d.has_auth) {
      anomalies.push('Authentication challenge (401/407) in dialog ' + d.call_id.substring(0,20));
    }
    // NAT detection: RFC1918 in Contact
    const rfc1918 = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/;
    const natIPs = [...d.contact_ips].filter(function(ip) { return rfc1918.test(ip); });
    if (natIPs.length) {
      anomalies.push('RFC 1918 address in Contact (' + natIPs.join(', ') + ') — NAT issue in dialog ' + d.call_id.substring(0,20));
    }

    // Build representative message flow (unique method+response sequence only)
    const flow = [];
    const seen = new Set();
    d.messages.forEach(function(m) {
      const key = m.request_line || m.status_line || '';
      const shortKey = key.split(' ').slice(0,2).join(' ');
      if (!seen.has(shortKey)) {
        seen.add(shortKey);
        const entry = {
          time: m.time,
          direction: m.src_ip + ':' + (m.src_port||'') + ' -> ' + m.dst_ip + ':' + (m.dst_port||''),
          message: key,
          from: m.from,
          to: m.to,
          via: m.via,
          contact: m.contact,
          cseq: m.cseq,
          user_agent: m.user_agent,
          content_type: m.content_type
        };
        flow.push(entry);
      }
    });

    return {
      call_id: d.call_id,
      duration_seconds: Math.round(duration * 100) / 100,
      message_count: d.messages.length,
      unique_flow: flow,
      methods: d.methods,
      responses: d.responses,
      user_agents: [...d.user_agents],
      contact_ips: [...d.contact_ips],
      via_ips: [...d.via_ips],
      has_bye: d.has_bye,
      has_cancel: d.has_cancel,
      has_auth: d.has_auth,
      result: d.responses.includes('200') ? 'answered' : (d.has_cancel ? 'cancelled' : 'unanswered')
    };
  });

  return {
    total_messages: messages.length,
    total_dialogs: dialogSummaries.length,
    answered: dialogSummaries.filter(function(d) { return d.result === 'answered'; }).length,
    unanswered: dialogSummaries.filter(function(d) { return d.result === 'unanswered'; }).length,
    cancelled: dialogSummaries.filter(function(d) { return d.result === 'cancelled'; }).length,
    dialogs: dialogSummaries,
    anomalies: anomalies
  };
}

// ── Smart summarize RTP streams ──
function summarizeRTP(streamSummaryText, rtpFields) {
  const streams = {};

  if (rtpFields) {
    rtpFields.split('\n').filter(Boolean).forEach(function(line) {
      const p = line.split('|');
      if (p.length < 10) return;
      const ssrc = p[6];
      const flow = p[2] + ':' + p[4] + '->' + p[3] + ':' + p[5];
      const key  = ssrc + '|' + flow;

      if (!streams[key]) {
        streams[key] = {
          ssrc: ssrc, flow: flow,
          src_ip: p[2], dst_ip: p[3],
          src_port: p[4], dst_port: p[5],
          payload_type: p[9],
          codec: codecName(p[9]),
          packet_count: 0,
          lost: 0,
          out_of_order: 0,
          marker_count: 0,
          total_bytes: 0,
          first_seq: parseInt(p[7]) || 0,
          last_seq:  parseInt(p[7]) || 0,
          first_time: parseFloat(p[1]) || 0,
          last_time:  parseFloat(p[1]) || 0,
          jitter_samples: [],
          prev_arrival: null,
          prev_send_ts: null,
          clock_rate: 8000
        };
      }

      const s   = streams[key];
      const seq = parseInt(p[7]) || 0;
      const ts  = parseFloat(p[1]) || 0;
      const rtp_ts = parseInt(p[8]) || 0;

      // Jitter calculation (RFC 3550)
      if (s.prev_arrival !== null && s.prev_send_ts !== null) {
        const d_arrival = (ts - s.prev_arrival) * s.clock_rate;
        const d_send    = Math.abs(rtp_ts - s.prev_send_ts);
        const d         = Math.abs(d_arrival - d_send);
        s.jitter_samples.push(d / s.clock_rate * 1000); // ms
      }
      s.prev_arrival = ts;
      s.prev_send_ts = rtp_ts;

      // Sequence gap / loss detection
      if (s.packet_count > 0) {
        const expected = (s.last_seq + 1) % 65536;
        if (seq !== expected) {
          const gap = (seq - s.last_seq - 1 + 65536) % 65536;
          if (gap > 0 && gap < 1000) s.lost += gap;
          if (seq < s.last_seq && gap > 32768) s.out_of_order++;
        }
      }

      if (p[10] === '1') s.marker_count++;
      s.last_seq   = seq;
      s.last_time  = ts;
      s.total_bytes += parseInt(p[12]) || 0;
      s.packet_count++;
    });
  }

  const anomalies = [];
  const result = Object.values(streams).map(function(s) {
    const duration   = s.last_time - s.first_time;
    const lossRate   = s.packet_count > 0 ? (s.lost / (s.packet_count + s.lost)) * 100 : 0;
    const avgJitter  = s.jitter_samples.length > 0
      ? s.jitter_samples.reduce(function(a,b){return a+b;},0) / s.jitter_samples.length
      : 0;
    const maxJitter  = s.jitter_samples.length > 0 ? Math.max.apply(null, s.jitter_samples) : 0;
    const mos        = calcMOS(lossRate, avgJitter);
    const bitrate    = duration > 0 ? Math.round((s.total_bytes * 8 / duration) / 1000) : 0;
    const pktRate    = duration > 0 ? Math.round(s.packet_count / duration) : 0;
    const ptime      = pktRate > 0 ? Math.round(1000 / pktRate) : 20;

    // Flag anomalies
    if (lossRate > 1)     anomalies.push('High packet loss ' + lossRate.toFixed(1) + '% on stream ' + s.flow + ' (MOS: ' + mos + ')');
    if (avgJitter > 30)   anomalies.push('High jitter ' + avgJitter.toFixed(1) + 'ms on stream ' + s.flow);
    if (mos < 3.5)        anomalies.push('Poor MOS ' + mos + ' on stream ' + s.flow + ' — call quality degraded');
    if (s.out_of_order > 5) anomalies.push('Out-of-order packets (' + s.out_of_order + ') on stream ' + s.flow);
    if (s.lost > 50)      anomalies.push('High absolute loss (' + s.lost + ' packets) on ' + s.flow);

    return {
      flow:             s.flow,
      ssrc:             s.ssrc,
      codec:            s.codec,
      payload_type:     s.payload_type,
      packet_count:     s.packet_count,
      duration_seconds: Math.round(duration * 100) / 100,
      loss_percent:     Math.round(lossRate * 100) / 100,
      avg_jitter_ms:    Math.round(avgJitter * 100) / 100,
      max_jitter_ms:    Math.round(maxJitter * 100) / 100,
      mos:              mos,
      bitrate_kbps:     bitrate,
      ptime_ms:         ptime,
      out_of_order:     s.out_of_order,
      marker_events:    s.marker_count,
      total_bytes:      s.total_bytes
    };
  });

  return { streams: result, anomalies: anomalies };
}

// ── Summarize RTCP ──
function summarizeRTCP(reports) {
  if (!reports.length) return { count: 0, summary: [] };
  const bySSRC = {};
  reports.forEach(function(r) {
    const key = r.ssrc || r.sender_ssrc || 'unknown';
    if (!bySSRC[key]) bySSRC[key] = { ssrc: key, sr: 0, rr: 0, bye: 0, loss_values: [], jitter_values: [] };
    const s = bySSRC[key];
    const pt = r.packet_type;
    if (pt === '200') s.sr++;
    if (pt === '201') s.rr++;
    if (pt === '203') s.bye++;
    if (r.fraction_lost && r.fraction_lost !== '') s.loss_values.push(parseInt(r.fraction_lost) || 0);
    if (r.jitter && r.jitter !== '') s.jitter_values.push(parseInt(r.jitter) || 0);
  });
  return {
    count: reports.length,
    summary: Object.values(bySSRC).map(function(s) {
      const avgLoss   = s.loss_values.length ? s.loss_values.reduce(function(a,b){return a+b;},0) / s.loss_values.length : 0;
      const avgJitter = s.jitter_values.length ? s.jitter_values.reduce(function(a,b){return a+b;},0) / s.jitter_values.length : 0;
      return {
        ssrc: s.ssrc,
        sender_reports: s.sr,
        receiver_reports: s.rr,
        bye_packets: s.bye,
        avg_fraction_lost: Math.round(avgLoss * 100) / 100,
        avg_jitter_units: Math.round(avgJitter)
      };
    })
  };
}

// ── Main analysis function ──
async function analyzePcap(filePath, filename) {
  const result = {
    filename: filename,
    summary: {},
    sip: {},
    sdp: { offers: [], answers: [] },
    rtp: {},
    rtcp: {},
    dtmf: { events: [] },
    tls: { sessions: [] },
    dns: { queries: [] },
    expert: '',
    conversations: {}
  };

  // 1. File summary
  try {
    const countOut = await run('tshark -r "' + filePath + '" 2>/dev/null | wc -l');
    result.summary.total_packets = parseInt(countOut) || 0;
    const durOut = await run('tshark -r "' + filePath + '" -T fields -e frame.time_relative 2>/dev/null | tail -1');
    result.summary.duration_seconds = parseFloat(durOut) || 0;
    const bytesOut = await run("tshark -r \"" + filePath + "\" -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END {print s}'");
    result.summary.total_bytes = parseInt(bytesOut) || 0;
    const protoOut = await run('tshark -r "' + filePath + '" -q -z io,phs 2>/dev/null');
    result.summary.protocol_hierarchy = protoOut;
  } catch(e) { result.summary.error = e.message; }

  // 2. SIP messages (all of them — we summarize in JS)
  try {
    const sipOut = await run(
      'tshark -r "' + filePath + '" -Y sip -T fields ' +
      '-e frame.number -e frame.time_relative -e ip.src -e ip.dst ' +
      '-e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport ' +
      '-e sip.Request-Line -e sip.Status-Line -e sip.Call-ID -e sip.CSeq ' +
      '-e sip.From -e sip.To -e sip.Via -e sip.Contact ' +
      '-e sip.User-Agent -e sip.content-type -e sip.Response-Code ' +
      '-E separator="|" 2>/dev/null'
    );
    const messages = [];
    if (sipOut) {
      sipOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        messages.push({
          frame: p[0], time: p[1],
          src_ip: p[2], dst_ip: p[3],
          src_port: p[4]||p[6]||'', dst_port: p[5]||p[7]||'',
          request_line: p[8], status_line: p[9],
          call_id: p[10], cseq: p[11],
          from: p[12], to: p[13],
          via: p[14], contact: p[15],
          user_agent: p[16], content_type: p[17],
          response_code: p[18]
        });
      });
    }
    result.sip = summarizeSIP(messages);

    // SIP dialog stats
    const statOut = await run('tshark -r "' + filePath + '" -q -z sip,stat 2>/dev/null');
    result.sip.tshark_stats = statOut;
  } catch(e) { result.sip = { error: e.message }; }

  // 3. SDP
  try {
    const sdpOut = await run(
      'tshark -r "' + filePath + '" -Y sip -T fields ' +
      '-e sip.Call-ID -e sip.Request-Line -e sip.Status-Line ' +
      '-e sdp.connection_info -e sdp.media -e sdp.media_attr -e sdp.bandwidth ' +
      '-E separator="|" 2>/dev/null'
    );
    if (sdpOut) {
      sdpOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        if (p[4] || p[5]) {
          const entry = {
            call_id: p[0],
            context: p[1] || p[2],
            connection: p[3],
            media_lines: p[4] ? p[4].split(',') : [],
            media_attrs: p[5] ? p[5].split(',') : [],
            bandwidth: p[6]
          };
          const isAnswer = p[2] && (p[2].includes('200') || p[2].includes('18'));
          if (isAnswer) result.sdp.answers.push(entry);
          else result.sdp.offers.push(entry);
        }
      });
    }
  } catch(e) {}

  // 4. RTP (capped at 100k packets for very large captures)
  try {
    const rtpSummary = await run('tshark -r "' + filePath + '" -q -z rtp,streams 2>/dev/null');
    const rtpFields  = await run(
      'tshark -r "' + filePath + '" -Y rtp -T fields ' +
      '-e frame.number -e frame.time_relative -e ip.src -e ip.dst ' +
      '-e udp.srcport -e udp.dstport -e rtp.ssrc -e rtp.seq ' +
      '-e rtp.timestamp -e rtp.p_type -e rtp.marker -e rtp.ext -e frame.len ' +
      '-E separator="|" 2>/dev/null | head -100000'
    );
    result.rtp = summarizeRTP(rtpSummary, rtpFields);
    result.rtp.tshark_stream_summary = rtpSummary;
  } catch(e) { result.rtp = { error: e.message }; }

  // 5. RTCP
  try {
    const rtcpOut = await run(
      'tshark -r "' + filePath + '" -Y rtcp -T fields ' +
      '-e frame.time_relative -e ip.src -e ip.dst -e rtcp.ssrc ' +
      '-e rtcp.pt -e rtcp.senderssrc -e rtcp.ssrc.fraction ' +
      '-e rtcp.ssrc.lost -e rtcp.ssrc.jitter -e rtcp.sender.packet_count ' +
      '-E separator="|" 2>/dev/null'
    );
    const reports = [];
    if (rtcpOut) {
      rtcpOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        reports.push({
          time: p[0], src_ip: p[1], dst_ip: p[2],
          ssrc: p[3], packet_type: p[4], sender_ssrc: p[5],
          fraction_lost: p[6], cumulative_lost: p[7],
          jitter: p[8], sender_packet_count: p[9]
        });
      });
    }
    result.rtcp = summarizeRTCP(reports);
  } catch(e) { result.rtcp = { error: e.message }; }

  // 6. DTMF
  try {
    const dtmfOut = await run(
      'tshark -r "' + filePath + '" -Y "rtp.p_type==101 || rtp.p_type==96 || rtp.p_type==97" ' +
      '-T fields -e frame.time_relative -e ip.src -e ip.dst ' +
      '-e rtp.telephone-event.event -e rtp.telephone-event.duration -e rtp.telephone-event.end ' +
      '-E separator="|" 2>/dev/null'
    );
    if (dtmfOut) {
      dtmfOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        if (p[3]) result.dtmf.events.push({ time: p[0], src: p[1], dst: p[2], digit: p[3], duration: p[4], end: p[5] });
      });
    }
  } catch(e) {}

  // 7. TLS/DTLS
  try {
    const tlsOut = await run(
      'tshark -r "' + filePath + '" -Y tls -T fields ' +
      '-e frame.time_relative -e ip.src -e ip.dst ' +
      '-e tls.handshake.type -e tls.handshake.version ' +
      '-e tls.handshake.ciphersuite -e tls.handshake.extensions_server_name -e tls.alert_message ' +
      '-E separator="|" 2>/dev/null | head -500'
    );
    if (tlsOut) {
      const typeMap = {'1':'ClientHello','2':'ServerHello','11':'Certificate','14':'ServerHelloDone','20':'Finished'};
      tlsOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        if (p[3]) result.tls.sessions.push({
          time: p[0], src: p[1], dst: p[2],
          type: typeMap[p[3]] || ('type='+p[3]),
          version: p[4], cipher: p[5], sni: p[6], alert: p[7]
        });
      });
    }
  } catch(e) {}

  // 8. DNS
  try {
    const dnsOut = await run(
      'tshark -r "' + filePath + '" -Y dns -T fields ' +
      '-e frame.time_relative -e ip.src -e dns.qry.name -e dns.qry.type -e dns.a -e dns.flags.response ' +
      '-E separator="|" 2>/dev/null | head -200'
    );
    if (dnsOut) {
      dnsOut.split('\n').filter(Boolean).forEach(function(line) {
        const p = line.split('|');
        result.dns.queries.push({ time: p[0], src: p[1], query: p[2], type: p[3], answer: p[4], is_response: p[5]==='1' });
      });
    }
  } catch(e) {}

  // 9. Expert info
  try {
    result.expert = await run('tshark -r "' + filePath + '" -q -z expert 2>/dev/null | head -80');
  } catch(e) {}

  // 10. Conversation summary
  try {
    result.conversations.udp = await run('tshark -r "' + filePath + '" -q -z conv,udp 2>/dev/null');
    result.conversations.tcp = await run('tshark -r "' + filePath + '" -q -z conv,tcp 2>/dev/null');
  } catch(e) {}

  // ── Format for Claude ──
  result.formatted_for_ai = formatForClaude(result);
  return result;
}

// ── Format intelligently for Claude ──
function formatForClaude(d) {
  const lines = [];
  lines.push('=== PCAP ANALYSIS: ' + d.filename + ' ===');
  lines.push('Packets: ' + d.summary.total_packets + ' | Duration: ' + d.summary.duration_seconds + 's | Bytes: ' + d.summary.total_bytes);
  if (d.summary.protocol_hierarchy) {
    lines.push('\nPROTOCOL HIERARCHY:\n' + d.summary.protocol_hierarchy);
  }

  // SIP
  if (d.sip && d.sip.total_dialogs > 0) {
    lines.push('\n=== SIP SUMMARY ===');
    lines.push('Total messages: ' + d.sip.total_messages + ' | Dialogs: ' + d.sip.total_dialogs);
    lines.push('Answered: ' + d.sip.answered + ' | Unanswered: ' + d.sip.unanswered + ' | Cancelled: ' + d.sip.cancelled);

    if (d.sip.anomalies && d.sip.anomalies.length) {
      lines.push('\nSIP ANOMALIES DETECTED:');
      d.sip.anomalies.forEach(function(a) { lines.push('  ⚠ ' + a); });
    }

    lines.push('\nDIALOG FLOWS:');
    d.sip.dialogs.forEach(function(dialog) {
      lines.push('\nCall-ID: ' + dialog.call_id);
      lines.push('  Result: ' + dialog.result + ' | Duration: ' + dialog.duration_seconds + 's | Messages: ' + dialog.message_count);
      lines.push('  Methods: ' + dialog.methods.join(', ') + ' | Responses: ' + dialog.responses.join(', '));
      if (dialog.user_agents.length) lines.push('  User-Agents: ' + dialog.user_agents.join(' / '));
      if (dialog.contact_ips.length) lines.push('  Contact IPs: ' + dialog.contact_ips.join(', '));
      if (dialog.via_ips.length)     lines.push('  Via IPs: ' + dialog.via_ips.join(', '));
      lines.push('  Message flow:');
      dialog.unique_flow.forEach(function(m) {
        lines.push('    [' + m.time + 's] ' + m.message + ' | ' + m.direction);
        if (m.from)         lines.push('      From: ' + m.from);
        if (m.to)           lines.push('      To: ' + m.to);
        if (m.via)          lines.push('      Via: ' + m.via);
        if (m.contact)      lines.push('      Contact: ' + m.contact);
        if (m.user_agent)   lines.push('      UA: ' + m.user_agent);
        if (m.content_type) lines.push('      Content-Type: ' + m.content_type);
      });
    });

    if (d.sip.tshark_stats) {
      lines.push('\nTSHARK SIP STATS:\n' + d.sip.tshark_stats);
    }
  }

  // SDP
  const allSDP = d.sdp.offers.concat(d.sdp.answers);
  if (allSDP.length) {
    lines.push('\n=== SDP SESSIONS ===');
    allSDP.forEach(function(s) {
      lines.push('Call-ID: ' + s.call_id + ' [' + s.context + ']');
      if (s.connection)     lines.push('  Connection: ' + s.connection);
      if (s.media_lines.length) lines.push('  Media: ' + s.media_lines.join(' | '));
      if (s.media_attrs.length) lines.push('  Attributes: ' + s.media_attrs.slice(0,20).join(' | '));
      if (s.bandwidth)      lines.push('  Bandwidth: ' + s.bandwidth);
    });
  }

  // RTP
  if (d.rtp && d.rtp.streams && d.rtp.streams.length) {
    lines.push('\n=== RTP STREAMS ===');
    if (d.rtp.anomalies && d.rtp.anomalies.length) {
      lines.push('RTP ANOMALIES:');
      d.rtp.anomalies.forEach(function(a) { lines.push('  ⚠ ' + a); });
    }
    d.rtp.streams.forEach(function(s) {
      lines.push('\nStream: ' + s.flow);
      lines.push('  SSRC: ' + s.ssrc + ' | Codec: ' + s.codec + ' (PT=' + s.payload_type + ')');
      lines.push('  Packets: ' + s.packet_count + ' | Duration: ' + s.duration_seconds + 's | Bitrate: ' + s.bitrate_kbps + ' kbps');
      lines.push('  Loss: ' + s.loss_percent + '% | Avg jitter: ' + s.avg_jitter_ms + 'ms | Max jitter: ' + s.max_jitter_ms + 'ms');
      lines.push('  MOS: ' + s.mos + ' | ptime: ' + s.ptime_ms + 'ms | Out-of-order: ' + s.out_of_order);
      lines.push('  Marker events: ' + s.marker_events);
    });
    if (d.rtp.tshark_stream_summary) {
      lines.push('\nTSHARK RTP SUMMARY:\n' + d.rtp.tshark_stream_summary);
    }
  }

  // RTCP
  if (d.rtcp && d.rtcp.count > 0) {
    lines.push('\n=== RTCP (' + d.rtcp.count + ' reports) ===');
    d.rtcp.summary.forEach(function(r) {
      lines.push('SSRC ' + r.ssrc + ': SR=' + r.sender_reports + ' RR=' + r.receiver_reports + ' BYE=' + r.bye_packets + ' | Avg loss fraction=' + r.avg_fraction_lost + ' | Avg jitter=' + r.avg_jitter_units + ' units');
    });
  }

  // DTMF
  if (d.dtmf && d.dtmf.events.length) {
    lines.push('\n=== DTMF EVENTS (' + d.dtmf.events.length + ') ===');
    d.dtmf.events.forEach(function(e) {
      lines.push('[' + e.time + 's] Digit: ' + e.digit + ' | ' + e.src + ' -> ' + e.dst + ' | Duration: ' + e.duration);
    });
  }

  // TLS
  if (d.tls && d.tls.sessions.length) {
    lines.push('\n=== TLS/DTLS (' + d.tls.sessions.length + ' events) ===');
    d.tls.sessions.slice(0, 30).forEach(function(t) {
      lines.push('[' + t.time + 's] ' + t.type + ' | ' + t.src + ' -> ' + t.dst);
      if (t.version) lines.push('  Version: ' + t.version);
      if (t.cipher)  lines.push('  Cipher: ' + t.cipher);
      if (t.sni)     lines.push('  SNI: ' + t.sni);
      if (t.alert)   lines.push('  ALERT: ' + t.alert);
    });
  }

  // DNS
  if (d.dns && d.dns.queries.length) {
    lines.push('\n=== DNS ===');
    d.dns.queries.filter(function(q) { return !q.is_response; }).slice(0,20).forEach(function(q) {
      lines.push('[' + q.time + 's] ' + q.query + ' (' + q.type + ')');
    });
  }

  // Expert info
  if (d.expert) {
    lines.push('\n=== TSHARK EXPERT INFO ===\n' + d.expert);
  }

  // Conversations
  if (d.conversations) {
    if (d.conversations.udp) lines.push('\n=== UDP CONVERSATIONS ===\n' + d.conversations.udp);
    if (d.conversations.tcp) lines.push('\n=== TCP CONVERSATIONS ===\n' + d.conversations.tcp);
  }

  const text = lines.join('\n');
  // Final safety cap: 80KB — should be more than enough for even very large captures
  // after summarization, but prevents any edge case from blowing up Claude
  if (text.length > 80000) {
    return text.substring(0, 80000) + '\n\n[Output capped at 80KB — capture was very large. Key findings above are complete.]';
  }
  return text;
}

// ── Routes ──
app.get('/', function(req, res) {
  res.json({ status: 'ok', service: 'SIPSymposium PCAP Analyzer', version: '2.0.0' });
});

// Claude proxy endpoint — handles large payloads that Netlify can't
app.post('/claude', checkApiKey, async function(req, res) {
  try {
    const { messages, model, max_tokens } = req.body;
    if (!messages) return res.status(400).json({ error: 'Missing messages' });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: model || 'claude-sonnet-4-20250514',
        max_tokens: max_tokens || 4000,
        messages: messages
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: 'Anthropic API error: ' + errText });
    }

    const data = await response.json();
    res.json(data);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/health', function(req, res) {
  exec('tshark --version 2>&1 | head -1', function(err, stdout) {
    res.json({ status: err ? 'degraded' : 'ok', tshark: err ? 'not found' : stdout.trim(), uptime: Math.round(process.uptime()) });
  });
});

app.post('/analyze', checkApiKey, upload.single('pcap'), async function(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded. Send .pcap as multipart/form-data field "pcap".' });
  }
  const filePath = req.file.path;
  const filename = req.file.originalname;
  console.log('[' + new Date().toISOString() + '] Analyzing: ' + filename + ' (' + req.file.size + ' bytes)');
  try {
    const result = await analyzePcap(filePath, filename);
    res.json({ success: true, filename: filename, file_size_bytes: req.file.size, analysis: result });
  } catch(e) {
    console.error('Analysis error:', e);
    res.status(500).json({ error: 'Analysis failed: ' + e.message });
  } finally {
    fs.unlink(filePath, function() {});
  }
});

app.listen(PORT, function() {
  console.log('SIPSymposium PCAP backend v2.0 running on port ' + PORT);
  exec('tshark --version 2>&1 | head -1', function(err, stdout) {
    if (err) console.warn('WARNING: tshark not found');
    else console.log('tshark: ' + stdout.trim());
  });
});
