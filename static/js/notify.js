// static/js/notify.js
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

  function formatAgo(iso) {
    const t = new Date(iso);
    if (isNaN(t)) return "방금 전";
    const diff = (Date.now() - t.getTime()) / 60000;
    if (diff < 1) return "방금 전";
    if (diff < 60) return `${Math.floor(diff)}분 전`;
    if (diff < 1440) return `${Math.floor(diff / 60)}시간 전`;
    return `${Math.floor(diff / 1440)}일 전`;
  }

  function renderBadge() {
    const count = notifList.querySelectorAll("li").length;
    badge.textContent = count;
    badge.classList.toggle("show", count > 0);
  }

  function isTransactionNotice(snippet) {
    return snippet && snippet.startsWith("[시스템]");
  }
  
  
  
   
  

  socket.on("dm_notify", d => {
    if (!d || d.sender_id === myId) return;

    const minId = Math.min(myId, d.partner_id);
    const maxId = Math.max(myId, d.partner_id);
    const roomId = `dm-${minId}-${maxId}-${d.product_id}`;
    if (currentRoom === roomId) return;

    const displayName = d.partner_name || d.partner_username || `사용자 ${d.partner_id}`;
    const productName = d.product_name || "(알 수 없는 상품)";
    const timeAgo = formatAgo(d.time);
    const transactionNotice = isTransactionNotice(d.snippet);
    const noticeText = transactionNotice ? "💰 거래 관련 알림이 도착했습니다!" : "새로운 메시지가 도착했습니다!";
    const key = `dm-${d.partner_id}-${d.product_id}-${d.time}`;

    if (!notifList.querySelector(`li[data-key="${key}"]`)) {
      notifList.insertAdjacentHTML("afterbegin", `
        <li data-key="${key}" data-partner="${Number(d.partner_id)}" data-product="${Number(d.product_id)}">
          <a href="/chat/${d.partner_id}?item=${d.product_id}">
            <strong>${displayName}</strong><br>
            <span>${noticeText}</span><br>
            <small style="color:#888">${productName} • ${timeAgo}</small>
          </a>
        </li>
      `);
    }
    renderBadge();
  });

  socket.on("connect", () => {
    socket.emit("load_notifications");
  });

  socket.on("notif_list", list => {
    notifList.innerHTML = "";
    list.forEach(d => {
      const key = `dm-${d.partner_id}-${d.product_id}-${d.time}`;
      const displayName = d.partner_name || `사용자 ${d.partner_id}`;
      const productName = d.product_name || "(알 수 없는 상품)";
      const timeAgo = formatAgo(d.time);
      const transactionNotice = isTransactionNotice(d.snippet);
      const noticeText = transactionNotice ? "💰 거래 관련 알림이 도착했습니다!" : "새로운 메시지가 도착했습니다!";

      notifList.insertAdjacentHTML("beforeend", `
        <li data-key="${key}" data-partner="${d.partner_id}" data-product="${d.product_id}">
          <a href="/chat/${d.partner_id}?item=${d.product_id}">
            <strong>${displayName}</strong><br>
            <span>${noticeText}</span><br>
            <small style="color:#888">${productName} • ${timeAgo}</small>
          </a>
        </li>
      `);
    });
    renderBadge();
});


  notifList.addEventListener("click", async (e) => {
    const li = e.target.closest("li[data-partner][data-product]");
    if (!li) return;
    const pid = parseInt(li.dataset.partner, 10);
    const prod = parseInt(li.dataset.product, 10);
    if (isNaN(pid) || isNaN(prod)) {
      console.error("Invalid partner_id or product_id:", li.dataset);
      return;
    }
    try {
      const res = await fetch("/notif/read", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ partner_id: pid, product_id: prod })
      });
      if (!res.ok) throw new Error("읽음 처리 실패");

      notifList.querySelectorAll(`li[data-partner="${pid}"][data-product="${prod}"]`).forEach(el => el.remove());
      renderBadge();
    } catch (err) {
      console.error("서버 요청 실패:", err);
    }
  });

  document.addEventListener("click", e => {
    if (!notifPanel.contains(e.target) && !notifBtn.contains(e.target)) {
      notifPanel.style.display = "none";
    }
  });
});
