document.addEventListener("DOMContentLoaded", () => {
  const socket = io();
  const notifBtn = document.getElementById("notif-btn");
  const notifPanel = document.getElementById("notif-panel");
  const notifList = notifPanel.querySelector("ul");
  const badge = document.getElementById("notif-count");
  const myId = Number(document.body.dataset.userid);
  let currentRoom = null;

  window.setCurrentRoom = (room) => currentRoom = room;
  window.clearCurrentRoom = () => currentRoom = null;

  notifBtn.onclick = () => {
    notifPanel.style.display = notifPanel.style.display === "block" ? "none" : "block";
  };

  // 유틸: 상대적 시간
  function formatAgo(iso) {
    const t = new Date(iso + "Z");
    if (isNaN(t)) return "방금 전";
    const diff = (Date.now() - t.getTime()) / 60000;
    if (diff < 1) return "방금 전";
    if (diff < 60) return `${Math.floor(diff)}분 전`;
    if (diff < 1440) return `${Math.floor(diff / 60)}시간 전`;
    return `${Math.floor(diff / 1440)}일 전`;
  }

  // 알림 수신
  // 알림 수신
socket.on("dm_notify", d => {
  if (!d || d.sender_id === myId) return;

  const minId = Math.min(myId, d.partner_id);
  const maxId = Math.max(myId, d.partner_id);
  const roomId = `dm-${minId}-${maxId}`;
  if (currentRoom === roomId) return;

  const displayName = d.partner_name || d.partner_username || `사용자 ${d.partner_id}`;
  const productName = d.product_name || "(알 수 없는 상품)";
  const timeAgo = formatAgo(d.time);

  const key = `dm-${d.partner_id}-${d.product_id}-${d.time}`;
  const already = notifList.querySelector(`li[data-key="${key}"]`);
  if (!already) {
    notifList.insertAdjacentHTML("afterbegin", `
      <li data-key="${key}">
        <a href="/chat/${d.partner_id}?item=${d.product_id}">
          <strong>${displayName}</strong>님<br>
          <span>새로운 메시지가 도착했습니다!</span><br>
          <small style="color:#888">${productName} • ${timeAgo}</small>
        </a>
      </li>
    `);
  }

  // ✅ 무조건 알림 수 만큼 뱃지 증가
  const current = parseInt(badge.textContent, 10) || 0;
  badge.textContent = current + 1;
  badge.classList.add("show");
  
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

document.addEventListener("click", e => {
  const panel = document.getElementById("notif-panel");
  const btn = document.getElementById("notif-btn");
  if (!panel.contains(e.target) && !btn.contains(e.target)) {
    panel.style.display = "none";
  }
});
