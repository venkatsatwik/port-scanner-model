# 🚀 Step-by-Step Guide: How to Upload PortSentinel to GitHub

This guide is designed for beginners. It will teach you how **Git** (version control) and **GitHub** (cloud code hosting) work, and how to upload this project step by step.

---

## 🧠 Part 1: Git vs. GitHub — What's the Difference?

- **Git** is a tool installed on your computer that tracks changes in your code like a timeline or "save game" system.
- **GitHub** is a website (owned by Microsoft) where you store your Git timeline online so you can share your work, collaborate with others, and showcase your portfolio to employers.

---

## 📥 Part 2: Installing Git on Windows

If you don't have Git installed on your computer yet:

### Option A: Using Windows Package Manager (Winget)
Open **PowerShell** as Administrator or normal user and run:
```powershell
winget install --id Git.Git -e --source winget
```

### Option B: Download the Official Installer
1. Visit the official download page: **[https://git-scm.com/download/win](https://git-scm.com/download/win)**
2. Download the **64-bit Git for Windows Setup**.
3. Run the installer (you can click **Next** on all default settings).
4. Restart your PowerShell or Command Prompt terminal.

### Verify Installation:
In your terminal, type:
```powershell
git --version
```
You should see: `git version 2.x.x...`

---

## ⚙️ Part 3: One-Time Configuration

Before your first commit, tell Git who you are. This information will appear next to your commits on GitHub:

```powershell
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```
*(Make sure to use the same email you use to log in to GitHub!)*

---

## 📁 Part 4: Step-by-Step Commands to Push to GitHub

### Step 1: Open Terminal in Project Folder
Navigate to your project directory:
```powershell
cd C:\Users\satwi\.gemini\antigravity\scratch\port-sentinel
```

### Step 2: Initialize Git in the Project
Turn this folder into a Git repository:
```powershell
git init
```
*(This creates a hidden `.git` folder that tracks your file history).*

### Step 3: Stage All Files
Add all your project files to the "staging area" (the list of files ready to be saved):
```powershell
git add .
```
*(Note: Thanks to `.gitignore`, temporary and cache files are automatically excluded).*

### Step 4: Make Your First Commit
Save your files into Git history with a descriptive message:
```powershell
git commit -m "feat: Initial commit for PortSentinel - PC Security & Port Auditor"
```

### Step 5: Rename Default Branch to `main`
```powershell
git branch -M main
```

---

## 🌐 Part 5: Create the Repository on GitHub

1. Open your web browser and go to **[https://github.com](https://github.com)** (sign in or create a free account).
2. In the top-right corner, click the **`+`** icon and select **New repository**.
3. Fill in the details:
   - **Repository name:** `port-sentinel`
   - **Description:** `A zero-dependency Python PC security auditor, multi-threaded port scanner, and secret connection detector with a modern web dashboard.`
   - **Public or Private:** Choose **Public** (so you can share it and show off your work!).
   - **Important:** Leave **"Add a README file"**, **"Add .gitignore"**, and **"Choose a license"** **UNCHECKED** (we already created them in your project!).
4. Click **Create repository**.

---

## 🔗 Part 6: Link and Push Your Code

On the page that appears after creating the repository, copy the URL under **"…or push an existing repository from the command line"**.

Run these two commands in your terminal (replace `YOUR_USERNAME` with your actual GitHub username):

```powershell
# 1. Link your local project to GitHub
git remote add origin https://github.com/YOUR_USERNAME/port-sentinel.git

# 2. Upload (push) your code to GitHub
git push -u origin main
```

A login window or browser prompt will appear asking you to authorize Git with your GitHub account. Follow the prompt to sign in!

Once complete, refresh your GitHub page in your browser — your code, README, documentation, and web dashboard files are now live! 🎉

---

## 🔄 Part 7: Making Future Updates

Whenever you make improvements or changes to the project in the future, follow this simple 3-step cycle:

```powershell
# 1. Stage the changed files
git add .

# 2. Save the change with a message
git commit -m "Updated scan speed and added new security rules"

# 3. Push to GitHub
git push
```

---

## ⭐ Pro Tips to Make Your GitHub Project Shine

1. **Add Topics/Tags:** On your GitHub repo page, click the gear icon next to "About" and add tags like: `python`, `cybersecurity`, `port-scanner`, `network-security`, `security-audit`.
2. **Add a Screenshot:** Run `run.bat`, take a screenshot of the dashboard in action, save it in the folder, and embed it into your `README.md`.
3. **Star your own repo:** Bookmark and star it on GitHub!
