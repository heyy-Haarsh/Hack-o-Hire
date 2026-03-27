// voice-pane.js — FraudShield Voice Deepfake Detector
// Standalone pane: record live call or upload audio, detect AI-generated voice

(function () {

    const VOICE_API = "https://localhost:3000/voice";

    let mediaRecorder = null;
    let audioChunks   = [];

    Office.onReady(function (info) {
        if (info.host === Office.HostType.Outlook) {
            document.getElementById("btn-record").addEventListener("click", startRecording);
            document.getElementById("btn-stop").addEventListener("click", stopRecording);
            document.getElementById("btn-upload-audio").addEventListener("change", uploadAudio);
        }
    });

    // ── Start microphone recording ─────────────────────────────────
    async function startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            audioChunks  = [];
            mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm" });

            mediaRecorder.ondataavailable = e => {
                if (e.data.size > 0) audioChunks.push(e.data);
            };

            mediaRecorder.start(100);

            setRecordingState(true);
            setResult('<span style="color:#856404">🔴 Recording... speak now</span>');

        } catch (err) {
            console.error("Mic error:", err);
            setResult('<span style="color:#dc3545">⚠ Microphone access denied. Allow microphone in browser settings.</span>');
        }
    }

    // ── Stop recording and analyze ─────────────────────────────────
    function stopRecording() {
        if (!mediaRecorder || mediaRecorder.state === "inactive") return;

        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(t => t.stop());

        setRecordingState(false);
        setResult('<span style="color:#666">Analyzing voice...</span>');

        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: "audio/webm" });
            await analyzeVoiceBlob(blob, "recording.webm");
        };
    }

    // ── Upload audio file ──────────────────────────────────────────
    async function uploadAudio(event) {
        const file = event.target.files[0];
        if (!file) return;
        setResult(`<span style="color:#666">Analyzing ${file.name}...</span>`);
        await analyzeVoiceBlob(file, file.name);
        event.target.value = "";
    }

    // ── Send audio blob to Voice API ───────────────────────────────
    async function analyzeVoiceBlob(blob, filename) {
        try {
            const formData = new FormData();
            formData.append("file", blob, filename);

            const response = await fetch(`${VOICE_API}/analyze/voice`, {
                method: "POST",
                body:   formData
            });

            if (!response.ok) throw new Error(`Voice API returned ${response.status}`);

            const result  = await response.json();
            const score   = result.risk_score;
            const verdict = result.verdict;
            const tier    = result.tier;
            const deep    = result.deep_score;
            const rf      = result.rf_score;
            const ms      = result.processing_ms;

            const color = score > 85 ? "#dc3545" :
                          score > 60 ? "#fd7e14" :
                          score > 30 ? "#ffc107" : "#28a745";

            const indicators = (result.top_indicators || []).slice(0, 3)
                .map(i => `<div style="font-size:11px;color:#666;margin:2px 0">• ${i}</div>`)
                .join("");

            setResult(`
                <div style="background:#f8f9fa;padding:10px;border-radius:6px;
                            border-left:4px solid ${color};margin-top:6px">
                    <div style="font-weight:600;color:${color};font-size:13px;margin-bottom:4px">
                        ${verdict} — ${tier} (${score}/100)
                    </div>
                    <div style="font-size:12px;color:#555;margin-bottom:4px">
                        Deep model: ${deep} &nbsp;|&nbsp; RF: ${rf} &nbsp;|&nbsp; ${ms}ms
                    </div>
                    ${indicators}
                </div>`);

        } catch (err) {
            console.error("Voice analysis failed:", err);
            setResult(
                '<span style="color:#dc3545">⚠ Voice API not reachable. ' +
                'Start: <code>cd fraudshield-voice/src &amp;&amp; python api.py</code></span>'
            );
        }
    }

    // ── UI helpers ─────────────────────────────────────────────────
    function setRecordingState(isRecording) {
        const btnRecord = document.getElementById("btn-record");
        const btnStop   = document.getElementById("btn-stop");
        btnRecord.disabled = isRecording;
        btnStop.disabled   = !isRecording;
    }

    function setResult(html) {
        document.getElementById("voice-result").innerHTML = html;
    }

})();
