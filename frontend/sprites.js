/* Pixel-art command centre renderer. Pure canvas, no assets: everything is drawn from tiny pixel maps. */
(function () {
  const W = 480, H = 270;
  const PAL = {
    red: "#d64545", blue: "#2f6fdf", manager: "#e0a030", backup: "#2e9e66", human: "#c9d3ea",
  };

  // 10x13 character. h=hair s=skin c=team colour d=dark e=eye w=white
  const BODY = [
    "...hhhh...",
    "..hhhhhh..",
    "..hssssh..",
    "..sesses..",
    "..ssssss..",
    "...ssss...",
    "..cccccc..",
    ".cccwwccc.",
    ".cscccccs.",
    ".s.cccc.s.",
    "...dddd...",
    "...d..d...",
    "..dd..dd..",
  ];
  const HAIR = { red: "#2b1a12", blue: "#e8d27a", manager: "#5a5a66", backup: "#1d3b2c", human: "#6b3e1f" };

  function drawSprite(ctx, x, y, team, frame, scale) {
    const hair = HAIR[team] || "#333";
    for (let r = 0; r < BODY.length; r++) {
      let row = BODY[r];
      if (frame && r >= 11) row = r === 11 ? "...dd.d..." : "...dd.dd..";
      for (let c = 0; c < row.length; c++) {
        const ch = row[c];
        if (ch === ".") continue;
        ctx.fillStyle = ch === "h" ? hair : ch === "s" ? "#f0c8a0" : ch === "c" ? PAL[team] : ch === "d" ? "#1d2333"
          : ch === "e" ? "#111" : "#fff";
        ctx.fillRect(Math.round(x + c * scale), Math.round(y + r * scale), scale, scale);
      }
    }
  }

  function room(ctx, x, y, w, h, floor, wall, label) {
    ctx.fillStyle = wall; ctx.fillRect(x, y, w, 14);
    for (let i = 0; i < w; i += 10) for (let j = 14; j < h; j += 10) {
      ctx.fillStyle = ((i + j) / 10) % 2 ? floor[0] : floor[1];
      ctx.fillRect(x + i, y + j, Math.min(10, w - i), Math.min(10, h - j));
    }
    ctx.strokeStyle = "#0a0f1c"; ctx.lineWidth = 2; ctx.strokeRect(x + 1, y + 1, w - 2, h - 2);
    ctx.fillStyle = "#fff"; ctx.font = "7px 'Press Start 2P', monospace"; ctx.textBaseline = "top";
    ctx.fillText(label, x + 5, y + 4);
  }

  function desk(ctx, x, y, on, t) {
    ctx.fillStyle = "#6b4a2b"; ctx.fillRect(x, y, 34, 12);
    ctx.fillStyle = "#4a321c"; ctx.fillRect(x, y + 12, 34, 3);
    ctx.fillStyle = "#222b3d"; ctx.fillRect(x + 9, y - 12, 16, 11);
    ctx.fillStyle = on ? (Math.floor(t / 200) % 2 ? "#7be0aa" : "#4fc48a") : "#36425c";
    ctx.fillRect(x + 11, y - 10, 12, 7);
    ctx.fillStyle = "#222b3d"; ctx.fillRect(x + 15, y - 1, 4, 2);
  }

  function plant(ctx, x, y) {
    ctx.fillStyle = "#8a5a32"; ctx.fillRect(x, y + 8, 8, 6);
    ctx.fillStyle = "#2e9e66"; ctx.fillRect(x - 2, y, 12, 9); ctx.fillStyle = "#3fc07f"; ctx.fillRect(x + 1, y - 3, 6, 5);
  }

  class Scene {
    constructor(canvas, bubbleLayer) {
      this.c = canvas; this.ctx = canvas.getContext("2d"); this.ctx.imageSmoothingEnabled = false;
      this.bubbles = bubbleLayer;
      this.homes = { red: [62, 92], manager: [222, 62], blue: [382, 92], backup: [0, 0] };
      this.vault = [222, 192];
      this.agents = {
        red: this.mk("red", this.homes.red), blue: this.mk("blue", this.homes.blue),
        manager: this.mk("manager", this.homes.manager),
      };
      this.sandboxBusy = 0; this.sandboxState = "idle"; this.verdict = null; this.t = 0;
      requestAnimationFrame((t) => this.loop(t));
    }
    mk(team, home) {
      return { team, x: home[0], y: home[1], tx: home[0], ty: home[1], status: "idle", bubble: null, bubbleUntil: 0 };
    }
    addBackup(side) {
      if (this.agents.backup) return;
      const home = side === "red" ? [100, 120] : [420, 120];
      this.homes.backup = home;
      this.agents.backup = this.mk("backup", [home[0], 10]);
      this.agents.backup.tx = home[0]; this.agents.backup.ty = home[1];
    }
    setStatus(agent, status) {
      const a = this.agents[agent]; if (!a) return;
      a.status = status;
      const home = this.homes[agent];
      if (status === "running" && (agent === "red" || agent === "blue") && this.sandboxBusy) {
        a.tx = this.vault[0] + (agent === "red" ? -40 : 40); a.ty = this.vault[1] - 20;
      } else { a.tx = home[0]; a.ty = home[1]; }
    }
    say(agent, text, ms = 6000) {
      const a = this.agents[agent] || (agent === "sandbox" ? null : this.agents.manager);
      if (!a) return;
      a.bubble = text.length > 140 ? text.slice(0, 137) + "..." : text;
      a.bubbleUntil = performance.now() + ms;
      a.bubbleTeam = agent;
    }
    sandbox(stateName) {
      this.sandboxState = stateName;
      this.sandboxBusy = stateName === "running" ? performance.now() : 0;
      for (const k of ["red", "blue"]) this.setStatus(k, this.agents[k].status);
    }
    loop(t) {
      this.t = t; this.draw(t); this.drawBubbles(t);
      requestAnimationFrame((tt) => this.loop(tt));
    }
    draw(t) {
      const ctx = this.ctx;
      ctx.fillStyle = "#0b1120"; ctx.fillRect(0, 0, W, H);
      room(ctx, 6, 30, 150, 150, ["#3a1e22", "#43242a"], "#5c2a2f", "RED TEAM");
      room(ctx, 166, 10, 148, 120, ["#3a3220", "#433a25"], "#5c4a26", "MANAGER HQ");
      room(ctx, 324, 30, 150, 150, ["#1c2a48", "#213153"], "#26406e", "BLUE TEAM");
      // corridor
      ctx.fillStyle = "#1a2133"; ctx.fillRect(156, 140, 168, 16); ctx.fillRect(60, 180, 40, 10); ctx.fillRect(380, 180, 40, 10);
      // sandbox vault
      const vx = 176, vy = 162, vw = 128, vh = 100;
      ctx.fillStyle = "#0f2219"; ctx.fillRect(vx, vy, vw, vh);
      const glow = this.sandboxState === "running" ? (Math.sin(t / 150) + 1) / 2 : 0;
      ctx.strokeStyle = this.sandboxState === "fail" ? "#d64545" : `rgba(46,158,102,${0.6 + glow * 0.4})`;
      ctx.lineWidth = 3; ctx.strokeRect(vx + 1.5, vy + 1.5, vw - 3, vh - 3);
      ctx.fillStyle = "#7be0aa"; ctx.font = "7px 'Press Start 2P', monospace"; ctx.fillText("SANDBOX", vx + 6, vy + 6);
      ctx.fillStyle = "#4b6b5c"; ctx.font = "5px 'Press Start 2P', monospace"; ctx.fillText("NO NET  NON-ROOT  RO", vx + 6, vy + 16);
      // container box
      const bx = vx + 44, by = vy + 40;
      ctx.fillStyle = this.sandboxState === "running" ? "#2f6fdf" : "#26324a"; ctx.fillRect(bx, by, 40, 26);
      ctx.fillStyle = "#0a0f1c"; for (let i = 0; i < 5; i++) ctx.fillRect(bx + 4 + i * 8, by + 3, 2, 20);
      if (this.sandboxState === "running") {
        ctx.fillStyle = "#e0a030"; const p = Math.floor(t / 120) % 4;
        ctx.fillRect(bx + 8 + p * 7, by - 6, 4, 4);
      }
      // bars
      ctx.fillStyle = "#3a5547"; for (let i = 0; i < vw; i += 12) ctx.fillRect(vx + i, vy + vh - 14, 2, 12);
      if (this.verdict) {
        ctx.fillStyle = this.verdict.color; ctx.font = "6px 'Press Start 2P', monospace";
        ctx.fillText(this.verdict.text, vx + 6, vy + 74);
      }
      // furniture
      desk(ctx, 45, 108, this.agents.red.status === "running", t);
      desk(ctx, 365, 108, this.agents.blue.status === "running", t);
      desk(ctx, 205, 78, this.agents.manager.status === "running", t);
      plant(ctx, 16, 46); plant(ctx, 140, 160); plant(ctx, 456, 46); plant(ctx, 334, 160); plant(ctx, 296, 26);
      // scoreboard on manager wall
      ctx.fillStyle = "#0a0f1c"; ctx.fillRect(250, 26, 56, 26);
      ctx.fillStyle = "#d64545"; ctx.font = "6px 'Press Start 2P', monospace"; ctx.fillText("R " + (this.score ? this.score.red : 0), 254, 30);
      ctx.fillStyle = "#7aa8ff"; ctx.fillText("B " + (this.score ? this.score.blue : 0), 254, 41);

      for (const k of Object.keys(this.agents)) {
        const a = this.agents[k];
        a.x += (a.tx - a.x) * 0.06; a.y += (a.ty - a.y) * 0.06;
        const moving = Math.abs(a.tx - a.x) + Math.abs(a.ty - a.y) > 1;
        const bob = a.status === "running" && !moving ? Math.round(Math.sin(t / 160)) : 0;
        drawSprite(ctx, a.x - 10, a.y - 26 + bob, a.team, moving && Math.floor(t / 150) % 2, 2);
        const lamp = { running: "#2e9e66", waiting: "#e0a030", failed: "#d64545", completed: "#c9d3ea" }[a.status];
        if (lamp) { ctx.fillStyle = lamp; ctx.fillRect(a.x - 2, a.y - 34, 4, 4); }
      }
    }
    drawBubbles(t) {
      const layer = this.bubbles; const rectW = this.c.clientWidth, rectH = this.c.clientHeight;
      const now = performance.now();
      for (const k of Object.keys(this.agents)) {
        const a = this.agents[k];
        let el = layer.querySelector(`[data-b="${k}"]`);
        if (!a.bubble || now > a.bubbleUntil) { if (el) el.remove(); continue; }
        if (!el) { el = document.createElement("div"); el.dataset.b = k; layer.appendChild(el); }
        el.className = "bubble " + (a.bubbleTeam || k);
        if (el.textContent !== a.bubble) el.textContent = a.bubble;
        el.style.left = (a.x / W) * rectW + "px";
        el.style.top = ((a.y - 38) / H) * rectH + "px";
        el.style.opacity = a.bubbleUntil - now < 600 ? "0" : "1";
      }
    }
  }
  window.VG = window.VG || {};
  window.VG.Scene = Scene;
})();
