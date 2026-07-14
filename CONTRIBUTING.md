# Contributing to WhyClick

Thank you for your interest in contributing!

**Invited collaborators** can open pull requests directly as usual.

**External contributors** (not yet invited) are welcome too — please follow the patch-by-email workflow below instead of opening a PR.

## How to submit a patch

We use `git format-patch` to keep things simple for external contributors. Please **do not** use `git send-email` — just attach the `.patch` file directly to an email.

### 1. Create your patch

Once your commit is ready on your local branch:

```bash
git format-patch HEAD~1
```

This produces a file like `0001-your-commit-message.patch` in the current directory.

For multiple commits:

```bash
git format-patch HEAD~N   # replace N with the number of commits
```

### 2. Send it by email

Send the `.patch` file as an **email attachment** to:

```
hello@adamiskandar.com
```

Use this exact subject line:

```
Subject: [PATCH] opalanet/WhyClick
```

And include your committer identity in the body:

```
From: Your Committer Name
<committer-email@example.org>
```

> **Note:** The committer name and email in the body should match how you signed your commit (`git config user.name` / `git config user.email`) — this identifies who authored the change. It does not have to be the same address you are sending from; you can use a different personal or work email to send the message.

#### Example

Say your commit was signed as `John Doe <johndoe@example.org>` but you are sending from your personal Gmail:

- **From (sender):** `johndoe@gmail.com`
- **Subject:** `[PATCH] opalanet/WhyClick`
- **Body:**
  ```
  From: John Doe
  <johndoe@example.org>
  ```
- **Attachment:** `0001-fix-ipv6-detection.patch`

---

## Why this workflow?

WhyClick lives under [Opala Network](https://github.com/opalanet), and we keep pull requests gated to invited collaborators. This is intentional — open PRs tend to attract spam, half-finished changes, and contributions that don't align with the project's direction or naming conventions. Running everything through email first lets us have a quick look before anything lands.

**Why not `git send-email`?**

`git send-email` requires setting up SMTP, which is genuinely overkill for sending a patch to one project you might contribute to once. Most modern developers have never touched it and shouldn't have to.

This workflow is actually borrowed from old-school kernel development — it's how Linus Torvalds and the Linux kernel team have handled patches for decades. The difference is we're not asking you to wrestle with SMTP configuration. Just attach the file to a regular email and hit send. Same idea, none of the complexity.
