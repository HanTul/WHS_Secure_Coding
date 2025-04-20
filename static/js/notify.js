document.addEventListener("DOMContentLoaded", () => {
  const socket      = io();
  const notifBtn    = document.getElementById("notif-btn");
  const notifPanel  = document.getElementById("notif-panel");
  const notifList   = notifPanel.querySelector("ul");
  const badge       = document.getElementById("dm-count");
  const myId        = Number(document.body.dataset.userid);
  let currentRoom   = null;

  notifBtn.onclick = () => {
    notifPanel.style.display =
      notifPanel.style.display === "block" ? "none" : "block";
  };

  // 유틸: 상대적 시간
  function formatAgo(iso) {
    try {
      const t = new Date(iso), diff = (Date.now() - t) / 60000;
      if (diff < 1) return "방금 전";
      if (diff < 60) return `${diff | 0}분 전`;
      return `${(diff / 60) | 0}시간 전`;
    } catch {
      return "";
    }
  }

  // 알림 수신
  socket.on("dm_notify", d => {
    if (!d || d.sender_id === myId) return;

    const key = `dm-${d.partner_id}-${d.product_id}-${d.time}`;
    if (notifList.querySelector(`li[data-key="${key}"]`)) return;

    // 채팅방 안에 있는 경우 무시
    const minId = Math.min(myId, d.partner_id);
    const maxId = Math.max(myId, d.partner_id);
    const roomId = `dm-${minId}-${maxId}`;
    if (currentRoom === roomId) return;

    notifList.insertAdjacentHTML("afterbegin", `
      <li data-key="${key}">
        <a href="/chat/${d.partner_id}?item=${d.product_id}">
          <strong>${d.partner_name}</strong><br>
          ${d.snippet}<br>
          <small style="color:#888">${d.product_name} • ${formatAgo(d.time)}</small>
        </a>
      </li>`);

    // badge 증가
    const current = Number(badge.textContent || 0);
    badge.textContent = current + 1;
    badge.hidden = false;
  });

  // 채팅방 변경 시 서버에 현재 방 알려주기
  window.setCurrentRoom = function(roomName) {
    currentRoom = roomName;
    socket.emit("current_room", { room: roomName });
  };

  window.clearCurrentRoom = function() {
    currentRoom = null;
    socket.emit("current_room", { room: null });
  };
});
