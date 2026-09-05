# -*- coding: utf-8 -*-
"""
generate_azure_setup_guide.py
Generates a professional PDF setup guide explaining how to deploy and configure the AICyberAuditBox system on Azure VM.
Run: python scripts/generate_azure_setup_guide.py
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos
import os, datetime

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "AZURE_SETUP_GUIDE.pdf")

# ── Color Palette ──────────────────────────────────────────────────────────
DARK_BG      = (15,  23,  42)      # Slate 900
ACCENT_BLUE  = (59, 130, 246)     # Sky Blue
ACCENT_GREEN = (34, 197,  94)     # Emerald Green
WHITE        = (255, 255, 255)
LIGHT_GRAY   = (241, 245, 249)     # Slate 100
MID_GRAY     = (148, 163, 184)     # Slate 400
DARK_TEXT    = (15,  23,  42)
BODY_TEXT    = (51,  65,  85)      # Slate 700


class SetupGuidePDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 12, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(10, 3)
        self.cell(0, 6, "AICyberAuditBox  --  Azure VM Setup & Deployment Guide", align="L")
        self.set_xy(0, 3)
        self.cell(200, 6, f"Page {self.page_no()}", align="R")
        self.ln(12)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 6, "CONFIDENTIAL  |  AICyberAuditBox Enterprise Installation Manual", align="C")

    def hline(self, color=LIGHT_GRAY, thickness=0.3):
        self.set_draw_color(*color)
        self.set_line_width(thickness)
        y = self.get_y()
        self.line(10, y, 200, y)
        self.ln(3)

    def section_title(self, text):
        self.ln(4)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*DARK_BG)
        self.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.hline(ACCENT_BLUE, 0.6)

    def body(self, text, size=9.5, color=BODY_TEXT, indent=0, is_bold=False):
        style = "B" if is_bold else ""
        self.set_font("Helvetica", style, size)
        self.set_text_color(*color)
        self.set_x(10 + indent)
        self.multi_cell(190 - indent, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def code_block(self, code_lines):
        self.ln(2)
        self.set_fill_color(30, 41, 59)  # Dark slate background
        self.set_text_color(241, 245, 249)  # Off white text
        self.set_font("Courier", "", 8.5)
        
        # Calculate box height
        line_height = 4.5
        box_height = len(code_lines) * line_height + 6
        
        # Get current Y position
        y = self.get_y()
        # Page break check
        if y + box_height > 275:
            self.add_page()
            y = self.get_y()
            
        self.rect(10, y, 190, box_height, "F")
        self.set_xy(14, y + 3)
        
        for line in code_lines:
            self.cell(0, line_height, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

    def step_header(self, num, title):
        self.ln(3)
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(*ACCENT_BLUE)
        self.cell(0, 7, f"Step {num}: {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)


def build_pdf():
    pdf = SetupGuidePDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(10, 14, 10)

    # ════════════════════════════════════════════
    # PAGE 1 -- COVER
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.set_fill_color(*DARK_BG)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_fill_color(*ACCENT_BLUE)
    pdf.rect(0, 110, 210, 3, "F")

    pdf.set_xy(0, 60)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(*WHITE)
    pdf.cell(210, 14, "AICyberAuditBox", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*ACCENT_BLUE)
    pdf.cell(210, 10, "AZURE VM SETUP & INSTALLATION GUIDE", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(5)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(*MID_GRAY)
    pdf.cell(210, 6, "Deploying a Local, Zero-Dependency Offline Compliance Engine", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Metadata box
    pdf.set_fill_color(30, 41, 59)
    pdf.rect(25, 140, 160, 85, "F")
    
    y0 = 146
    metrics = [
        ("Deployment Target", "Microsoft Azure Cloud (IaaS Virtual Machine)"),
        ("OS Architecture",   "Windows Server 2022 / Windows 10 Pro Pro"),
        ("Active Backend",    "llama.cpp (llama-server.exe) CPU-optimized"),
        ("Local Database",    "PostgreSQL Master-Slave Docker Containers"),
        ("Web Interface",     "FastAPI + Uvicorn (HTTPS Port 443, SSL Enabled)"),
        ("Auto-Start Trigger", "Windows Task Scheduler (On Windows Logon)"),
        ("Author / Owner",    "veeresh988V / LocalAuditShakti"),
        ("Report Date",       datetime.date.today().strftime("%B %d, %Y")),
    ]
    for label, value in metrics:
        pdf.set_xy(30, y0)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*MID_GRAY)
        self_w = pdf.get_string_width(label.upper() + "   ")
        pdf.cell(48, 8, label.upper(), align="L")
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*WHITE)
        pdf.cell(100, 8, value, align="L")
        y0 += 9

    # Bottom footer accent
    pdf.set_fill_color(*ACCENT_BLUE)
    pdf.rect(0, 280, 210, 17, "F")
    pdf.set_xy(0, 284)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*WHITE)
    pdf.cell(210, 6, "CONFIDENTIAL -- Enterprise Setup Manual", align="C")

    # ════════════════════════════════════════════
    # PAGE 2 -- INTRODUCTION & NETWORK SETUP
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("1. Introduction & Core Requirements")
    
    intro_txt = (
        "This installation guide outlines the exact, step-by-step procedure to set up the "
        "AICyberAuditBox compliance auditing application on an Azure Virtual Machine. "
        "To ensure compliance with strict privacy guidelines, all auditing computations "
        "(document ingestion, paragraph splitting, vector embeddings, and LLM text generation) "
        "happen completely locally within the VM virtualized space. No external API calls are made."
    )
    pdf.body(intro_txt)
    
    pdf.ln(3)
    pdf.body("System Specifications Requirement:", is_bold=True)
    pdf.body("  - CPU: Minimum 8 physical cores (optimal cores matching thread settings).", indent=4)
    pdf.body("  - Memory: 16GB RAM minimum (required to load llama.cpp models and PostgreSQL replication DB).", indent=4)
    pdf.body("  - Storage: 50GB SSD space (for GGUF model files and Docker volumes).", indent=4)
    pdf.body("  - Docker: Docker Desktop (configured with WSL2 backend).", indent=4)

    pdf.section_title("2. Azure VM Provisioning & Security Group Settings")
    
    setup_txt = (
        "When creating the VM in the Microsoft Azure Portal, select a Windows Server 2022 Datacenter "
        "or Windows 10 Pro image. During provisioning, you must allow RDP (port 3389) and explicitly "
        "allow inbound HTTPS connections (port 443) to the AICyberAuditBox dashboard."
    )
    pdf.body(setup_txt)
    
    pdf.step_header("1.1", "Add Inbound Rule in Azure Portal (Network Security Group)")
    pdf.body("To access the dashboard from your personal laptop without connecting via RDP:")
    pdf.body("  1. In the Azure Portal, open your Virtual Machine page.", indent=4)
    pdf.body("  2. Navigate to Networking -> Network settings (left sidebar).", indent=4)
    pdf.body("  3. Click Add inbound port rule and enter the following settings:", indent=4)
    
    pdf.ln(2)
    pdf.body("     - Source: Any", is_bold=True)
    pdf.body("     - Source Port Ranges: *", is_bold=True)
    pdf.body("     - Destination: Any", is_bold=True)
    pdf.body("     - Destination Port Ranges: 443", is_bold=True)
    pdf.body("     - Protocol: TCP", is_bold=True)
    pdf.body("     - Action: Allow", is_bold=True)
    pdf.body("     - Priority: 1000", is_bold=True)
    pdf.body("     - Name: Allow_HTTPS", is_bold=True)
    
    # ════════════════════════════════════════════
    # PAGE 3 -- CLONING & MODEL DOWNLOAD
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3. Repository Deployment & Model Ingestion")
    
    repo_txt = (
        "Log in to the VM via Remote Desktop (RDP). Open PowerShell and configure the code base "
        "and offline language models. The project contains pre-compiled binaries of llama-server.exe "
        "and expects offline models to be placed in the project root."
    )
    pdf.body(repo_txt)
    
    pdf.step_header("2.1", "Clone the Branch & Verify Update")
    pdf.body("Navigate to the desktop directory (or your preferred root directory) and execute:")
    
    pdf.code_block([
        "cd C:\\Users\\veeresh988V\\Desktop\\llama",
        "git clone -b kv-cache https://github.com/AISecurityComplianceAuditOps/AICyberSecurityAuditBoxV.git",
        "cd AICyberSecurityAuditBoxV"
    ])
    
    pdf.step_header("2.2", "Acquire Model GGUFs")
    pdf.body(
        "Copy or download the required GGUF files to the root of the project directory "
        "(C:\\Users\\veeresh988V\\Desktop\\llama\\AICyberSecurityAuditBoxV\\):"
    )
    pdf.body("  - LLM Model: google_gemma-4-E4B-it-Q4_K_M.gguf (approx. 2.6GB)", indent=4)
    pdf.body("  - Embedding Model: nomic-embed-text-v1.5.f16.gguf (approx. 270MB)", indent=4)
    
    pdf.step_header("2.3", "Start Docker Daemon")
    pdf.body(
        "Open Docker Desktop inside the VM. Ensure that WSL2 integration is fully active "
        "and that the Docker service is running (green status icon)."
    )
    
    # ════════════════════════════════════════════
    # PAGE 4 -- CONFIGURE AUTOMATED SCHEDULER
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("4. Automated Startup Configuration (Auto-Logon & Task)")
    
    sch_txt = (
        "To ensure that the auditing application automatically launches whenever the Azure VM is started "
        "(either scheduled or powered on via mobile), we configure Windows Auto-Logon and a logon task. "
        "Auto-Logon triggers a background user session, launching Docker Desktop and the pipeline "
        "automatically without requiring manual RDP connection."
    )
    pdf.body(sch_txt)
    
    pdf.step_header("3.1", "Configure Windows Auto-Logon (PowerShell)")
    pdf.body("Run this block in PowerShell as Administrator inside the VM. Replace the password:")
    
    pdf.code_block([
        "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"AutoAdminLogon\" -Value \"1\"",
        "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"DefaultUserName\" -Value \"veeresh988V\"",
        "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"DefaultPassword\" -Value \"veeresh988V@\""
    ])
    
    pdf.step_header("3.2", "Register the Windows Task Scheduler Task")
    pdf.body("Create the scheduled task which executes at logon (automatically triggered by Auto-Logon):")
    
    pdf.code_block([
        "# Define path parameters",
        "$projectDir = \"C:\\Users\\veeresh988V\\Desktop\\llama\\AICyberSecurityAuditBoxV\"",
        "$batPath = \"$projectDir\\run_llamacpp_demo.bat\"",
        "",
        "# Define execution action",
        "$action = New-ScheduledTaskAction -Execute \"cmd.exe\" -Argument \"/c `\"$batPath`\"\" -WorkingDirectory $projectDir",
        "",
        "# Define trigger (runs automatically as the user logs on)",
        "$trigger = New-ScheduledTaskTrigger -AtLogon",
        "",
        "# Configure task limits and robustness",
        "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365)",
        "",
        "# Register task with administrative privileges",
        "Register-ScheduledTask -TaskName \"AICyberAuditBox_Startup\" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force"
    ])
    
    # ════════════════════════════════════════════
    # PAGE 5 -- VERIFICATION & TESTING
    # ════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("5. Application Verification & Maintenance")
    
    ver_txt = (
        "Once configured, you can power off the VM to test the automated startup logic. "
        "Ensure the server initializes correctly and is reachable externally."
    )
    pdf.body(ver_txt)
    
    pdf.step_header("4.1", "Verify Startup Logic")
    pdf.body("  1. Restart your Azure VM from the portal (or from the Azure mobile app).", indent=4)
    pdf.body("  2. Do not log in using RDP.", indent=4)
    pdf.body("  3. Wait approximately 60 seconds (giving Windows time to load the model).", indent=4)
    pdf.body("  4. Open a browser on your laptop (or any other device) and go to:", indent=4)
    pdf.body("     https://localauditshakti.centralindia.cloudapp.azure.com", is_bold=True, indent=8)
    
    pdf.step_header("4.2", "Manual Startup & Shutdown (For Maintenance)")
    pdf.body("If you are logged into the VM via RDP, you can control the engine manually using PowerShell:")
    
    pdf.body("Manual Start:", is_bold=True)
    pdf.code_block([
        "Start-ScheduledTask -TaskName \"AICyberAuditBox_Startup\""
    ])
    
    pdf.body("Manual Clean Stop (stops all servers and docker DB):", is_bold=True)
    pdf.code_block([
        "taskkill /F /IM llama-server.exe /T",
        "taskkill /F /IM streamlit.exe /T",
        "cd C:\\Users\\veeresh988V\\Desktop\\llama\\AICyberSecurityAuditBoxV",
        "docker-compose down"
    ])
    
    pdf.hline()
    pdf.body("Troubleshooting Notes:", is_bold=True)
    pdf.body("  - Connection Timeout: Verify that Azure NSG port 443 (HTTPS) inbound rule is active in the Network Security Group.", indent=4)
    pdf.body("  - SSL Certificate Error: Ensure cert.pem and key.pem exist in the application root folder.", indent=4)
    pdf.body("  - LLM Server fails: Verify GGUF files exist in root folder and model name is correct.", indent=4)
    pdf.body("  - Database fails: Open Docker Desktop and verify that the WSL2 subsystem is active.", indent=4)

    pdf.output(OUTPUT_PATH)
    print(f"Generated Azure setup guide PDF at {OUTPUT_PATH}")

if __name__ == "__main__":
    build_pdf()
