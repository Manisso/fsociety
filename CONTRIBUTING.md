<h1 align="center"> CHARTER OF CONTRIBUTION</h1>
At  FSociety development you can be a part of our family by just giving out a pull request and your worthy contribution. Legally you  are called offeror and we are called offeeree but we have more privileges then you.

**For your first couple of PR's, start with something small to get familiar with the project and its development processes. Please do not start by adding a new application, library or other large component.**
## Issue policy

Unlike many other software projects, FSociety is not concerned with gaining the largest possible userbase. Its target audience is its own developers. As such, we have limited interest in feature requests from non-contributors.

That said, please do file any bugs you find, keeping the following in mind:

* One issue per bug. Putting multiple things in the same issue makes both discussion and completion unnecessarily complicated.
* No build issues (or other support requests). If the GitHub Actions CI build succeeds, the build problem is most likely on your side. Work it out locally.
* Don't comment on issues just to add a joke or irrelevant commentary. Hundreds of people get notified about comments so let's keep them relevant.
* For bare metal issues, please include the complete debug log from the serial console and what you tried to do to solve the issue before opening the issue. Don't forget to add the hardware model of your machine and relevant details about it, to help us diagnose what is the problem.
## Human language policy

In FSociety, we treat human language as seriously as we do programming language.

**The following applies to all user-facing strings, code, comments, and commit messages:**

* The official project language is American English with ISO 8601 dates and metric units.
* Use proper spelling, grammar, and punctuation.
* Write in an authoritative and technical tone.

Everyone is encouraged to make use of tooling (spell checkers, etc) to make this easier.
## Code submission policy

Nobody is perfect, and sometimes we mess things up. That said, here are some good dos & dont's to try and stick to:

**Do:**


* Choose expressive variable, function and class names. Make it as obvious as possible what the code is doing.
* Split your changes into separate, atomic commits (i.e. A commit per feature or fix, where the build, tests and the system are all functioning).
* Make sure your commits are rebased on the master branch.
* Wrap your commit messages at 72 characters.
* The first line of the commit message is the subject line, and should have the format "Category: Brief description of what's being changed". The "category" can be a subdirectory, but also something like "POSIX compliance" or "ClassName". Whatever seems logical.
* Write the commit message subject line in the imperative mood ("Foo: Change the way dates work", not "Foo: Changed the way dates work").
* Write your commit messages in proper English, with care and punctuation.
* Squash your commits when making revisions after a patch review.
* Add your personal copyright line to PR when making substantive changes. (Optional but encouraged!)
* Check the spelling of your code, comments and commit messages.

**Don't:**

* Submit code that's incompatible with the project licence (MIT.)
* Touch anything outside the stated scope of the PR.
* Iterate excessively on your design across multiple commits.
* Use weasel-words like "refactor" or "fix" to avoid explaining what's being changed.
* End commit message subject lines with a period.
* Include commented-out code.
* Write in C or any programming language except python.
* Attempt large architectural changes until you are familiar with the system and have worked on it for a while.
## Pull Request Q&A

### I've submitted a PR and it passes CI. When can I expect to get first reviewer feedback?

While unadvertised PR's may get randomly merged by curious reviewers. Time may apply.

### If my PR isn't getting attention, how long should I wait before pinging one of the project reviewers?

Ping them right away if it's something urgent! If it's less urgent, then please avoid pinging it.

### Who are the project reviewers?
Only [Maniso](https://github.com/Manisso) is reveiwer by now!

### Is there a policy for branches/PRs that haven't been touched in X days? Should they be closed?

No,any such policy is not yet implemented but maybe a "stale bot" can be introduced in near future

### Are there specific people to reach out to for help in hacking?

In theory, the best person to speak with is whoever wrote most code adjacent to what you're working on. In practice, asking in one of the development channels on Discord is usually easier/better, since that allows many people to join the discussion. But you can specifically reach on Github that is better then a discord server.
**Please note that neither me or any contributor shall be subjected liable for hacking. So use this software for positive purpose and education. Don't blame me or anyone else!**
