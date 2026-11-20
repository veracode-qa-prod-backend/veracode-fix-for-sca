const fs = require('fs');
const path = require('path');
const core = require('@actions/core');
const github = require('@actions/github');

/**
 * Posts the PR comment for a completed fix run.
 *
 * SAST posts the comment directly to the original PR's conversation (this action already
 * holds a token with issues:write/pull_requests:write on the target repo, used by create-pr.js
 * to open the fix PR). SCA no longer posts from here: veracode-github-app now builds the
 * comment itself from the sca-fix-report.md uploaded in the "fix-for-sca-artifacts" artifact
 * (post-action.js), so there is nothing for this action to do for the SCA path.
 */
async function uploadPrComment(workspaceDir, repository, prNumber, githubToken, githubApiUrl, sourceCodeDir, isSastFix = false, fixPrNumber = null, fixPrUrl = null) {
  const [owner, repo] = repository.split('/');
  if (!owner || !repo) {
    throw new Error(`Invalid repository format. Expected 'owner/repo', got '${repository}'`);
  }

  if (isSastFix) {
    await postSastCommentDirectly(owner, repo, prNumber, githubToken, sourceCodeDir, fixPrNumber, fixPrUrl);
    return;
  }

  core.info('SCA PR comment is posted by veracode-github-app from sca-fix-report.md. Nothing to do here.');
}

async function postSastCommentDirectly(owner, repo, prNumber, githubToken, sourceCodeDir, fixPrNumber, fixPrUrl) {
  try {
    const reportPath = path.join(sourceCodeDir, 'sast-fix-report.md');
    let commentBody;
    if (fs.existsSync(reportPath)) {
      const reportContent = fs.readFileSync(reportPath, 'utf8');
      commentBody = generateSastCommentBody(reportContent, fixPrNumber, fixPrUrl);
    } else {
      core.warning(`sast-fix-report.md not found at ${reportPath}. Posting default comment.`);
      commentBody = '## Veracode Fix for SAST\n\nNo automated fixes were generated for the submitted findings.\n';
    }

    const octokit = github.getOctokit(githubToken);
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: parseInt(prNumber, 10),
      body: commentBody
    });
    core.info(`Posted SAST fix comment directly to PR #${prNumber} in ${owner}/${repo}`);

    // Clean up now that both the PR body (create-pr.js) and this comment have used the report.
    try {
      if (fs.existsSync(reportPath)) {
        fs.unlinkSync(reportPath);
      }
    } catch (cleanupError) {
      core.warning(`Failed to clean up sast-fix-report.md: ${cleanupError.message}`);
    }
  } catch (error) {
    core.warning(`Failed to post SAST fix comment: ${error.message}`);
  }
}

/**
 * Builds the fixed-format comment posted on the original PR: a PR link, the fix IDs and
 * CWE IDs pulled out of the enriched sast-fix-report.md, and a constant 4-step Next Steps list.
 * The full per-CWE breakdown stays in the Fix PR's own description (create-pr.js uses the
 * report as-is there); this comment is a short pointer to it.
 */
function generateSastCommentBody(reportContent, fixPrNumber, fixPrUrl) {
  const fixIds = extractFixIds(reportContent);
  const cwes = extractCwes(reportContent);

  let body = fixPrNumber
    ? '## Veracode Fix for SAST - Pull Request Created\n\n'
    : '## Veracode Fix for SAST\n\n';

  if (fixPrNumber && fixPrUrl) {
    body += `**PR:** [#${fixPrNumber}](${fixPrUrl})\n\n`;
  }

  if (fixIds.length > 0) {
    body += `This PR contains automated fixes for the SAST vulnerability: ${fixIds.map((id) => `\`${id}\``).join(' ')}\n\n`;
  }

  if (cwes.length > 0) {
    body += `Applying fixes for the following CWE IDs: ${cwes.map((cwe) => `${cwe.label} CWE-${cwe.id}`).join('  ')}\n\n`;
  }

  body += '**Next Steps:**\n';
  if (fixPrNumber) {
    body += '1. Review the changes in the Fix for SAST PR.\n';
    body += '2. Verify that tests pass.\n';
    body += '3. Merge the PR to apply the security fixes.\n';
    body += '4. Re-run the SAST scan to verify the fixes.\n';
  } else {
    body += '1. Re-run the SAST scan to verify the fixes.\n';
  }

  return body;
}

/**
 * Pulls distinct Fix IDs out of the report's "Fix ID: ..." lines, in first-seen order.
 * Tolerates the label and/or value being wrapped in markdown emphasis (`**Fix ID:**`)
 * or inline code (`` `SAST-xxxx-xx` ``).
 */
function extractFixIds(reportContent) {
  const fixIds = [];
  const seen = new Set();
  const regex = /Fix ID:[*`\s]*([^\n`]+)/g;
  let match;
  while ((match = regex.exec(reportContent)) !== null) {
    for (const rawId of match[1].split(',')) {
      const id = rawId.trim().replace(/^[*`\s]+|[*`\s]+$/g, '');
      if (id && !seen.has(id)) {
        seen.add(id);
        fixIds.push(id);
      }
    }
  }
  return fixIds;
}

const SEVERITY_EMOJI = ['🔴', '🟠', '🟡', '🟢', '🔵'];

/**
 * Pulls distinct "<severity emoji> CWE-<id>" entries (written by appendSeverityToReport
 * in run-fix-sast.js) out of the report, in first-seen order.
 */
function extractCwes(reportContent) {
  const cwes = [];
  const seen = new Set();
  const regex = new RegExp(`(${SEVERITY_EMOJI.join('|')})\\s*\`?CWE-(\\d+)\`?`, 'g');
  let match;
  while ((match = regex.exec(reportContent)) !== null) {
    if (!seen.has(match[2])) {
      seen.add(match[2]);
      cwes.push({ id: match[2], label: match[1] });
    }
  }
  return cwes;
}

module.exports = uploadPrComment;
