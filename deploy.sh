#!/bin/bash
# ============================================================
# DEPLOY SCRIPT — raj-ai-insight GitHub Pages
# Run this from the project folder to push to GitHub
# ============================================================

echo "🚀 Deploying raj-ai-insight to GitHub Pages..."

# STEP 1: Initialize git if not already done
if [ ! -d ".git" ]; then
  git init
  echo "✅ Git initialized"
fi

# STEP 2: Add all files
git add .
git commit -m "Launch: From Mythos to Fable — June 2026"

# STEP 3: Set your GitHub remote (replace YOUR_USERNAME with your GitHub username)
# git remote add origin https://github.com/YOUR_USERNAME/raj-ai-insight.git

# STEP 4: Push to GitHub
# git branch -M main
# git push -u origin main

# STEP 5: Enable GitHub Pages
# Go to: github.com/YOUR_USERNAME/raj-ai-insight → Settings → Pages
# Source: Deploy from branch → main → / (root)
# Your site will be live at: https://YOUR_USERNAME.github.io/raj-ai-insight/

echo ""
echo "📋 Manual Steps:"
echo "1. Create a new repo at github.com/new named: raj-ai-insight"
echo "2. Run: git remote add origin https://github.com/YOUR_USERNAME/raj-ai-insight.git"
echo "3. Run: git branch -M main && git push -u origin main"
echo "4. Go to repo Settings → Pages → Deploy from main branch"
echo "5. Your site URL: https://YOUR_USERNAME.github.io/raj-ai-insight/"
echo ""
echo "✅ Done. Files ready to push."
