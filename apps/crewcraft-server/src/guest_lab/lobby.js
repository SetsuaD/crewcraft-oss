"use strict";

const form = document.getElementById("join-form");
const invite = document.getElementById("invite");
const displayName = document.getElementById("display-name");
const lookup = document.getElementById("lookup");
const knock = document.getElementById("knock");
const meeting = document.getElementById("meeting");
const meetingTitle = document.getElementById("meeting-title");
const meetingHost = document.getElementById("meeting-host");
const notice = document.getElementById("notice");
const leave = document.getElementById("leave");

const pollInterval = 5000;
const rateBackoff = 15000;
const lobbyMessages = {
  waiting: "Waiting for the host to admit you.",
  admitted: "The host admitted you.",
  declined: "Your request to join was declined.",
  removed: "You have been removed from the lobby.",
};

let proof = "";
let poll = null;
let active = null;

function announce(message) {
  if (notice.textContent !== message) {
    notice.textContent = message;
  }
}

function cancelPoll() {
  clearTimeout(poll);
  poll = null;
}

function clearLobby() {
  cancelPoll();
  active?.abort();
  active = null;
  proof = "";
  form.reset();
  form.hidden = false;
  lookup.disabled = false;
  knock.disabled = false;
  leave.hidden = true;
  leave.disabled = false;
  meeting.hidden = true;
  meetingTitle.textContent = "";
  meetingHost.textContent = "";
  announce("");
}

async function request(operation, body, bearer = "") {
  active?.abort();
  const controller = new AbortController();
  active = controller;
  const timeout = setTimeout(() => controller.abort(), 8000);
  const headers = { "Content-Type": "application/json" };
  if (bearer) {
    headers.Authorization = `Bearer ${bearer}`;
  }
  let result;
  try {
    const response = await fetch(`/v1/guest/${operation}`, {
      method: "POST",
      credentials: "omit",
      mode: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = response.ok && response.status !== 204 ? await response.json() : null;
    result = { status: response.status, data };
  } catch {
    result = { status: 0, data: null };
  } finally {
    clearTimeout(timeout);
  }
  if (active !== controller) {
    return null;
  }
  active = null;
  return result;
}

function setFormBusy(busy) {
  lookup.disabled = busy;
  knock.disabled = busy;
}

function inviteCode() {
  return invite.value.trim().toUpperCase();
}

invite.addEventListener("input", () => {
  meeting.hidden = true;
  if (!active) {
    announce("");
  }
});

lookup.addEventListener("click", async () => {
  if (lookup.disabled || !invite.reportValidity()) {
    return;
  }
  const code = inviteCode();
  setFormBusy(true);
  announce("Checking the invite…");
  const result = await request("lookup", { code });
  if (!result) {
    return;
  }
  setFormBusy(false);
  if (code !== inviteCode()) {
    announce("");
    return;
  }
  if (result.status === 200 && typeof result.data?.title === "string" && typeof result.data.hostName === "string") {
    meetingTitle.textContent = result.data.title;
    meetingHost.textContent = `Hosted by ${result.data.hostName}`;
    meeting.hidden = false;
    announce("Invite found.");
  } else {
    meeting.hidden = true;
    if (result.status === 429) {
      announce("The lobby is busy. Wait a moment before trying again.");
    } else if (result.status === 404) {
      announce("This invite is unavailable.");
    } else {
      announce("The invite could not be checked. Try again.");
    }
  }
});

function showLobbyState(state) {
  if (state === "declined" || state === "removed") {
    clearLobby();
    invite.focus();
  }
  announce(lobbyMessages[state]);
}

function checkAgain(delay = pollInterval) {
  cancelPoll();
  if (proof) {
    poll = setTimeout(checkStatus, delay);
  }
}

async function checkStatus() {
  const result = await request("status", {}, proof);
  if (!result) {
    return;
  }
  if (result.status === 200 && Object.hasOwn(lobbyMessages, result.data?.state)) {
    showLobbyState(result.data.state);
  } else if (result.status === 404) {
    clearLobby();
    invite.focus();
    announce("This lobby is no longer available.");
  } else {
    announce("The lobby status is temporarily unavailable. Checking again shortly.");
  }
  checkAgain(result.status === 429 ? rateBackoff : pollInterval);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (knock.disabled) {
    return;
  }
  setFormBusy(true);
  announce("Sending your request to join…");
  const result = await request("knock", { code: inviteCode(), name: displayName.value });
  if (!result) {
    return;
  }
  setFormBusy(false);
  const guestProof = result.data?.proof;
  if (result.status === 201 && typeof guestProof === "string" && /^[A-Za-z0-9_-]{64}$/.test(guestProof) && Object.hasOwn(lobbyMessages, result.data.state)) {
    proof = guestProof;
    form.reset();
    form.hidden = true;
    leave.hidden = false;
    leave.focus();
    showLobbyState(result.data.state);
    checkAgain();
  } else if (result.status === 429) {
    announce("The lobby is busy. Wait a moment before trying again.");
  } else if (result.status === 400) {
    announce("Check your display name and invite code, then try again.");
  } else if (result.status === 404) {
    announce("This lobby is unavailable.");
  } else {
    announce("The join result is unknown. Check with the host before trying again.");
  }
});

leave.addEventListener("click", async () => {
  cancelPoll();
  leave.disabled = true;
  announce("Leaving the lobby…");
  const result = await request("leave", {}, proof);
  if (!result) {
    return;
  }
  if (result.status === 204 || result.status === 404) {
    clearLobby();
    invite.focus();
    announce(result.status === 204 ? "You left the lobby." : "This lobby is no longer available.");
  } else {
    leave.disabled = false;
    announce("The lobby could not confirm that you left. You can try again.");
    checkAgain(result.status === 429 ? rateBackoff : pollInterval);
  }
});

window.addEventListener("pagehide", clearLobby);
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    clearLobby();
  }
});
