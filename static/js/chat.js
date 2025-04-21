document.addEventListener("DOMContentLoaded", () => {
  const socket      = io();
  const chatBtn     = document.getElementById("public-chat-button");
  const popup       = document.getElementById("public-chat-popup");
  const tabs        = document.querySelectorAll(".tab");
  const tabPublic   = document.getElementById("tab-public");
  const tabDm       = document.getElementById("tab-dm");
  const boxPublic   = document.getElementById("chat-box-public");
  const inputPublic = document.getElementById("chat-input-public");
  const badgePublic = document.getElementById("public-chat-unread");
  const listPreview = document.getElementById("chat-history-list");
  const myId        = Number(document.body.dataset.userid);
  let pubUnread     = 0;
  let popupOpen     = false;
  let currentRoom   = null;

  window.setCurrentRoom = (room) => currentRoom = room;
  window.clearCurrentRoom = () => currentRoom = null;

  tabs.forEach(btn => {
    btn.onclick = () => {
      tabs.forEach(t => t.classList.toggle("active", t === btn));
      tabPublic.classList.toggle("hidden", btn.dataset.tab !== "public");
      tabDm.classList.toggle("hidden", btn.dataset.tab !== "dm");
    };
  });

  chatBtn.onclick = () => {
    popupOpen = !popupOpen;
    popup.style.display = popupOpen ? "flex" : "none";
    if (popupOpen) {
      pubUnread = 0;
      badgePublic.hidden = true;
      chatBtn.classList.remove("has-unread");
      setTimeout(() => boxPublic.scrollTop = boxPublic.scrollHeight, 50);
    }
  };

  socket.emit("load_public_history");
  socket.on("public_history", logs => {
    boxPublic.innerHTML = "";
    logs.forEach(addPublicChat);
    boxPublic.scrollTop = boxPublic.scrollHeight;
  });

  socket.on("message", d => {
    addPublicChat(d);
    if (!popupOpen && d.sender_id !== myId) {
      pubUnread++;
      badgePublic.textContent = pubUnread;
      badgePublic.hidden = false;
      chatBtn.classList.add("has-unread");
    }
    setTimeout(() => boxPublic.scrollTop = boxPublic.scrollHeight, 10);
  });

  function addPublicChat(d) {
    const mine = d.sender_id === myId;
    boxPublic.insertAdjacentHTML("beforeend", `
      <div class="chat-entry ${mine ? "chat-right" : "chat-left"}">
        <div class="sender">${d.username}</div>
        <div class="chat-msg">${d.msg}</div>
        <div class="time">${formatTime(d.time)}</div>
      </div>`);
  }

  inputPublic.onkeydown = e => {
    if (e.key === "Enter") {
      const msg = inputPublic.value.trim();
      if (msg) socket.emit("message", msg);
      inputPublic.value = "";
    }
  };

  socket.on("connect", () => {
    socket.emit("request_dm_preview");
    socket.emit("join_dm", { room: `user-${myId}` });  // 🔥 추가!
  });

  socket.on("dm_preview_update", previews => {
    listPreview.innerHTML = "";
    let unreadCnt = 0;
    previews.sort((a, b) => new Date(b.time) - new Date(a.time));
    previews.forEach(p => {
      const key = `${p.partner_id}-${p.product_id}`;
      const isUnread = !p.read;
      listPreview.insertAdjacentHTML("beforeend", `
        <li class="chat-preview ${isUnread ? "unread" : ""}" data-key="${key}">
          <a class="chat-link" href="${p.link}">
            <div class="chat-header">
              <span class="chat-username">${p.username}</span>
              <span class="chat-time">${formatAgo(p.time)}</span>
            </div>
            <div class="chat-message">${p.last_msg}</div>
            <div class="chat-meta">${p.product_name}</div>
          </a>
        </li>`);
      if (isUnread) unreadCnt++;
    });
  });

  socket.on("dm_refresh", d => {
    if (!d) return;
    const key = `${d.partner_id}-${d.product_id}`;
    listPreview.querySelector(`li[data-key="${key}"]`)?.remove();
  
    const myPartnerId = d.partner_id;
    const myRoom = `dm-${Math.min(myId, myPartnerId)}-${Math.max(myId, myPartnerId)}`;
  
    listPreview.insertAdjacentHTML("afterbegin", `
      <li class="chat-preview ${!d.read ? "unread" : ""}" data-key="${key}">
        <a class="chat-link" href="/chat/${d.partner_id}?item=${d.product_id}">
          <div class="chat-header">
            <span class="chat-username">${d.partner_name}</span>
            <span class="chat-time">${formatAgo(d.time)}</span>
          </div>
          <div class="chat-message">${d.snippet}</div>
          <div class="chat-meta">${d.product_name}</div>
        </a>
      </li>`);
  
  });

  listPreview.addEventListener("click", e => {
    const li = e.target.closest("li.chat-preview");
    if (!li) return;
    li.classList.remove("unread");
    const remain = listPreview.querySelectorAll("li.unread").length;
  });

  function formatAgo(iso) {
    const t = new Date(iso + "Z");  // Z는 이미 붙어 있음
    if (isNaN(t)) return "방금 전";
    const diff = (Date.now() - t.getTime()) / 60000;
    if (diff < 1) return "방금 전";
    if (diff < 60) return `${Math.floor(diff)}분 전`;
    return `${Math.floor(diff / 60)}시간 전`;
  }

  function formatTime(iso) {
    const t = new Date(iso);
    return t.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" });
  }
});
