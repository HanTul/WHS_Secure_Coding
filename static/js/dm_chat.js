// static/js/dm_chat.js
document.addEventListener("DOMContentLoaded", () => {
  const socket  = io();
  const room    = document.querySelector("meta[name='room']")?.content;
  const itemId  = document.querySelector("meta[name='item']")?.content;
  const userId  = Number(document.body.dataset.userid);
  const box     = document.getElementById("chat-box");
  const input   = document.getElementById("chat-input");

  // 메시지 시간 렌더링 (기존 메시지 포함)
  function renderAllTimes() {
    box.querySelectorAll(".message").forEach(msgEl => {
      const iso = msgEl.dataset.time;
      if (!iso) return;
      const d = new Date(iso);  // ← 여기
      if (isNaN(d)) return;
  
      const h = d.getHours();
      const m = d.getMinutes();
      const dispH = h % 12 || 12;
      const ampm = h < 12 ? "오전" : "오후";
      const text = `${ampm} ${dispH.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}`;
      const timeEl = msgEl.querySelector(".msg-time");
      if (timeEl) timeEl.textContent = text;
    });
  }
  

  // 스크롤 아래로 이동
  function scrollToBottom() {
    if (box) box.scrollTop = box.scrollHeight;
  }

  // 초기 렌더링 처리
  renderAllTimes();
  scrollToBottom();

  // 현재 방 정보 서버에 전달
  if (room) {
    socket.emit("join_dm", { room });
    socket.emit("current_room", { room });
    window.setCurrentRoom?.(room);  // notify.js 연동
  }
  socket.on("connect", () => {
    socket.emit("request_dm_preview");
  });
  // 메시지 수신
  // 메시지 수신 시
  socket.on("dm_message", data => {
    const isSelf = data.sender_id === userId;

    const outer = document.createElement("div");
    outer.className       = "message";
    outer.dataset.time    = data.time;
    outer.style.margin    = "8px 0";
    outer.style.textAlign = isSelf ? "right" : "left";

    const bubble = document.createElement("div");
    bubble.textContent       = data.msg;
    bubble.style.display     = "inline-block";
    bubble.style.padding     = "8px 14px";
    bubble.style.borderRadius= "16px";
    bubble.style.maxWidth    = "70%";
    bubble.style.wordBreak   = "break-word";
    bubble.style.background  = isSelf ? "#cde0ff" : "#eee";

    const timeDiv = document.createElement("div");
    timeDiv.className     = "msg-time";
    timeDiv.style.fontSize= "11px";
    timeDiv.style.color   = "#888";
    timeDiv.style.marginTop = "4px";

    outer.append(bubble, timeDiv);
    box.appendChild(outer);

    renderAllTimes();  // 🔁 여기서 시간 표시됨
    scrollToBottom();
  });

  

  // 메시지 전송
  input.addEventListener("keydown", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      const msg = input.value.trim();
      if (msg && room) {
        socket.emit("dm_message", { room, msg, product_id: itemId });
        input.value = "";
      }
    }
  });

  // 나가기 처리
  window.addEventListener("beforeunload", () => {
    socket.emit("current_room", { room: null });
    window.clearCurrentRoom?.();  // notify.js 연동
  });
});
