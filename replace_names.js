const fs = require('fs');

const slackPath = 'backend/mock-data/slack.json';
let slackContent = fs.readFileSync(slackPath, 'utf8');
slackContent = slackContent.replace(/"tanmayshukla60"/g, '"tanmayshukla60-netizen"');
slackContent = slackContent.replace(/"Tanmay Shukla"/g, '"tanmayshukla60-netizen"');
slackContent = slackContent.replace(/"tanmay60"/g, '"tanmayshukla60-netizen"');
slackContent = slackContent.replace(/"contractor_x"/g, '"tanmayshukla60-netizen"');
fs.writeFileSync(slackPath, slackContent);

const githubPath = 'backend/mock-data/github.json';
let githubContent = fs.readFileSync(githubPath, 'utf8');
githubContent = githubContent.replace(/"contractor_x"/g, '"tanmayshukla60-netizen"');
githubContent = githubContent.replace(/"tanmay60"/g, '"tanmayshukla60-netizen"');
fs.writeFileSync(githubPath, githubContent);

const testGeminiPath = 'backend/test_gemini.js';
let testGeminiContent = fs.readFileSync(testGeminiPath, 'utf8');
testGeminiContent = testGeminiContent.replace(/"tanmay60"/g, '"tanmayshukla60-netizen"');
fs.writeFileSync(testGeminiPath, testGeminiContent);

const sessionGithubPath = 'backend/sessions/tanmay1/mock-data/github.json';
if (fs.existsSync(sessionGithubPath)) {
  let sessionGithubContent = fs.readFileSync(sessionGithubPath, 'utf8');
  sessionGithubContent = sessionGithubContent.replace(/"contractor_x"/g, '"tanmayshukla60-netizen"');
  sessionGithubContent = sessionGithubContent.replace(/"tanmay60"/g, '"tanmayshukla60-netizen"');
  fs.writeFileSync(sessionGithubPath, sessionGithubContent);
}

const sessionSlackPath = 'backend/sessions/tanmay1/mock-data/slack.json';
if (fs.existsSync(sessionSlackPath)) {
  let sessionSlackContent = fs.readFileSync(sessionSlackPath, 'utf8');
  sessionSlackContent = sessionSlackContent.replace(/"tanmayshukla60"/g, '"tanmayshukla60-netizen"');
  sessionSlackContent = sessionSlackContent.replace(/"Tanmay Shukla"/g, '"tanmayshukla60-netizen"');
  sessionSlackContent = sessionSlackContent.replace(/"tanmay60"/g, '"tanmayshukla60-netizen"');
  sessionSlackContent = sessionSlackContent.replace(/"contractor_x"/g, '"tanmayshukla60-netizen"');
  fs.writeFileSync(sessionSlackPath, sessionSlackContent);
}

console.log('Names updated successfully.');
