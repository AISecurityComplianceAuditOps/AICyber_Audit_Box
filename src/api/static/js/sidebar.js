// ── SIDEBAR & SCOPE SELECTOR MODULE ──

function setAnalysisMode(mode) {
    selectedAnalysisMode = mode;
    const btnQuick = document.getElementById("btn-mode-quick");
    const btnDeep = document.getElementById("btn-mode-deep");
    const radioDeep = document.getElementById("radio-mode-deep");
    const radioQuick = document.getElementById("radio-mode-quick");

    if (mode === "Quick") {
        if (btnQuick) {
            btnQuick.classList.add("active");
            btnQuick.style.background = "#2563eb";
            btnQuick.style.color = "#ffffff";
            btnQuick.style.fontWeight = "700";
            btnQuick.style.outline = "none";
            btnQuick.style.boxShadow = "0 2px 6px rgba(37, 99, 235, 0.4)";
        }
        if (btnDeep) {
            btnDeep.classList.remove("active");
            btnDeep.style.background = "transparent";
            btnDeep.style.color = "#94a3b8";
            btnDeep.style.fontWeight = "500";
            btnDeep.style.outline = "none";
            btnDeep.style.boxShadow = "none";
        }
        if (radioQuick) radioQuick.checked = true;
    } else {
        if (btnDeep) {
            btnDeep.classList.add("active");
            btnDeep.style.background = "#2563eb";
            btnDeep.style.color = "#ffffff";
            btnDeep.style.fontWeight = "700";
            btnDeep.style.outline = "none";
            btnDeep.style.boxShadow = "0 2px 6px rgba(37, 99, 235, 0.4)";
        }
        if (btnQuick) {
            btnQuick.classList.remove("active");
            btnQuick.style.background = "transparent";
            btnQuick.style.color = "#94a3b8";
            btnQuick.style.fontWeight = "500";
            btnQuick.style.outline = "none";
            btnQuick.style.boxShadow = "none";
        }
        if (radioDeep) radioDeep.checked = true;
    }
}

function toggleCollapsible(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (el.style.display === "none" || el.style.display === "") {
        el.style.display = "block";
    } else {
        el.style.display = "none";
    }
}
