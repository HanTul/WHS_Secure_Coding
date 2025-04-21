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

  // 상대적 시간
  function formatAgo(iso) {
    const t = new Date(iso + "Z");
    if (isNaN(t)) return "방금 전";
    const diff = (Date.now() - t.getTime()) / 60000;
    if (diff < 1) return "방금 전";
    if (diff < 60) return `${Math.floor(diff)}분 전`;
    if (diff < 1440) return `${Math.floor(diff / 60)}시간 전`;
    return `${Math.floor(diff / 1440)}일 전`;
  }

  // 새로운 알림 실시간 수신
  // dm_notify 수신 시
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
        <li data-key="${key}" data-partner="${Number(d.partner_id)}" data-product="${Number(d.product_id)}">
          <a href="/chat/${d.partner_id}?item=${d.product_id}">
            <strong>${displayName}</strong>님<br>
            <span>새로운 메시지가 도착했습니다!</span><br>
            <small style="color:#888">${productName} • ${timeAgo}</small>
          </a>
        </li>
      `);
    }

    // ✅ 정확한 배지 카운트 반영
    const count = notifList.querySelectorAll("li").length;
    badge.textContent = count;

    // ✅ .show 클래스 강제 적용
    if (count > 0) {
      badge.classList.add("show");
    } else {
      badge.classList.remove("show");
    }
  });


  // 서버로부터 읽지 않은 알림 목록 받아오기
  socket.on("connect", () => {
    socket.emit("load_notifications");
  });

  // 초기 알림 렌더링
  socket.on("notif_list", list => {
    notifList.innerHTML = "";
  
    list.forEach(d => {
      const key = `dm-${d.partner_id}-${d.product_id}-${d.time}`;
      const displayName = d.partner_name || `사용자 ${d.partner_id}`;
      const productName = d.product_name || "(알 수 없는 상품)";
      const timeAgo = formatAgo(d.time);
  
      notifList.insertAdjacentHTML("beforeend", `
        <li data-key="${key}" data-partner="${d.partner_id}" data-product="${d.product_id}">
          <a href="/chat/${d.partner_id}?item=${d.product_id}">
            <strong>${displayName}</strong><br>
            <span>새로운 메시지가 도착했습니다!</span><br>
            <small style="color:#888">${productName} • ${timeAgo}</small>
          </a>
        </li>
      `);
    });
  
    const count = notifList.querySelectorAll("li").length;
    badge.textContent = count;
  
    if (count > 0) {
      badge.classList.add("show");
    } else {
      badge.classList.remove("show");
    }
  });
  
  
  

  // 알림 클릭 시 서버에 읽음 처리 요청 + 같은 방 알림 전부 제거
  notifList.addEventListener("click", async (e) => {
    const li = e.target.closest("li[data-partner][data-product]");
    if (!li) return;
  
    // 🔥 정확하게 정수로 파싱
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
  
      // 같은 방 알림 모두 제거
      notifList.querySelectorAll(`li[data-partner="${pid}"][data-product="${prod}"]`)
        .forEach(el => el.remove());
  
      const remain = notifList.querySelectorAll("li").length;
      badge.textContent = remain;
      if (remain > 0) {
        badge.classList.add("show");
      } else {
        badge.classList.remove("show");
      }
  
    } catch (err) {
      console.error("서버 요청 실패:", err);
    }
  });
  
  
  

  // 패널 외부 클릭 시 닫기
  document.addEventListener("click", e => {
    const panel = document.getElementById("notif-panel");
    const btn = document.getElementById("notif-btn");
    if (!panel.contains(e.target) && !btn.contains(e.target)) {
      panel.style.display = "none";
    }
  });
});
