const userId = Number(document.body.dataset.userid);
const partnerId = Number(document.querySelector("meta[name='partner-id']")?.content);
const itemId = document.querySelector("meta[name='item']")?.content;
const room = `dm-${Math.min(userId, partnerId)}-${Math.max(userId, partnerId)}-${itemId}`;
const socket = io();

document.addEventListener("DOMContentLoaded", () => {
  let transactionId = document.querySelector("meta[name='transaction']")?.content;
  const transactionStatus = document.querySelector("meta[name='transaction-status']")?.content;
  let buyerId = Number(document.querySelector("meta[name='buyer-id']")?.content);
  let sellerId = Number(document.querySelector("meta[name='seller-id']")?.content);

  const box = document.getElementById("chat-box");
  const input = document.getElementById("chat-input");
  const btnArea = document.getElementById("transaction-buttons");
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

  function renderAllTimes() {
    box.querySelectorAll(".message").forEach(msgEl => {
      const iso = msgEl.dataset.time;
      if (!iso) return;
      const d = new Date(iso);
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

  function scrollToBottom() {
    if (box) box.scrollTop = box.scrollHeight;
  }

  function escapeHtml(unsafe) {
    return unsafe.replace(/[&<>"']/g, m => (
      {'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;'}[m]
    ));
  }

  function decodeHtml(html) {
    const txt = document.createElement("textarea");
    txt.innerHTML = html;
    return txt.value;
  }
  

  function renderTransactionButtons(status, tid = null) {
    if (!btnArea) return;
    btnArea.innerHTML = "";
    if (tid) {
      transactionId = tid;
    }
    const isBuyer = userId === buyerId;
    const isSeller = userId === sellerId;
    if (status === "waiting_payment" && isBuyer) {
      addButton("송금하기", "pay");
      addButton("거래 취소", "cancel");
    } else if (status === "paid") {
      if (isSeller) {
        addButton("발송 완료", "ship");
        addButton("거래 취소", "cancel");
      } else if (isBuyer) {
        addButton("거래 취소", "cancel");
      }
    } else if (status === "shipped" && isBuyer) {
      addButton("수령 확인", "receive");
    }
  }

  function addButton(label, action) {
    const btn = document.createElement("button");
    btn.textContent = label;
    btn.style.padding = "8px 12px";
    btn.style.border = "1px solid #ccc";
    btn.style.borderRadius = "8px";
    btn.style.cursor = "pointer";
    btn.style.backgroundColor = "#f0f0f0";
    btn.onclick = () => handleTransactionAction(action);
    btnArea.appendChild(btn);
  }

  async function handleTransactionAction(action) {
    if (!transactionId) {
      alert("거래가 없습니다.");
      return;
    }
    try {
      const res = await fetch(`/transaction/${transactionId}/${action}`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        }
      });
      const data = await res.json();
      if (data.ok) {
        location.reload();
      } else {
        alert(data.error || "요청 실패");
      }
    } catch (err) {
      alert("서버 오류: " + err);
    }
  }

  renderAllTimes();
  scrollToBottom();
  if (transactionId && transactionStatus) {
    renderTransactionButtons(transactionStatus);
  }

  if (room) {
    socket.emit("join_dm", { room });
    socket.emit("current_room", { room });
    window.setCurrentRoom?.(room);
  }

  socket.on("connect", () => {
    socket.emit("request_dm_preview");
  });

  socket.on("dm_message", data => {
    const isSystem = data.is_system;
    const isSelf = data.sender_id === userId;
    const outer = document.createElement("div");
    outer.dataset.time = data.time;
  
    if (isSystem) {
      outer.className = "system-message";
      const msgText = document.createElement("div");
      msgText.className = "system-content";
      msgText.textContent = data.msg;
      outer.appendChild(msgText);
    } else {
      outer.className = "message";
      outer.style.margin = "8px 0";
      outer.style.textAlign = isSelf ? "right" : "left";
  
      const bubble = document.createElement("div");
      bubble.innerHTML = decodeHtml(data.msg);
      bubble.style.display = "inline-block";
      bubble.style.padding = "8px 14px";
      bubble.style.borderRadius = "16px";
      bubble.style.maxWidth = "70%";
      bubble.style.wordBreak = "break-word";
      bubble.style.background = isSelf ? "#cde0ff" : "#eee";
  
      const timeDiv = document.createElement("div");
      timeDiv.className = "msg-time";
      timeDiv.style.fontSize = "11px";
      timeDiv.style.color = "#888";
      timeDiv.style.marginTop = "4px";
  
      outer.append(bubble, timeDiv);
    }
    box.appendChild(outer);
    renderAllTimes();
    scrollToBottom();
  });

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

  window.addEventListener("beforeunload", () => {
    socket.emit("current_room", { room: null });
    window.clearCurrentRoom?.();
  });

  if ((!transactionId || transactionStatus === "canceled") && userId !== sellerId) {
    btnArea.innerHTML = `
      <button id="start-transaction-btn"
        style="padding:8px 12px; border:1px solid #ccc; border-radius:8px; cursor:pointer; background-color:#f0f0f0;">
        거래 시작
      </button>`;
    const startBtn = document.getElementById("start-transaction-btn");
    startBtn.onclick = async () => {
      if (!itemId || !partnerId) return;
      try {
        const res = await fetch(`/transaction/start/${itemId}/${partnerId}`, {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
          }
        });
        const data = await res.json();
        if (data.ok) {
          transactionId = data.transaction_id;
          buyerId = userId;
          sellerId = partnerId;
          location.reload();
          renderTransactionButtons("waiting_payment", transactionId);
        } else {
          alert(data.error || "거래 시작 실패");
        }
      } catch (err) {
        alert("서버 오류: " + err);
      }
    };
  }
});
