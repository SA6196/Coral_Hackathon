const fs = require('fs');
let f = fs.readFileSync('backend/src/coral/fetchRealData.js', 'utf8');

// There are three places we need to patch: 
// 1. In fetchGithub where we map PR authors
f = f.replace(/pr\.user\.login/g, 'pr.user.login === "tanmay60" ? "tanmayshukla60-netizen" : pr.user.login');

// 2. In fetchGithub where we map commit secrets/malicious findings
f = f.replace(/commitObj\.author\?\.login \|\| commitObj\.commit\?\.author\?\.name \|\| "unknown"/g, 
'(commitObj.author?.login || commitObj.commit?.author?.name || "unknown").replace(/^tanmay60$/i, "tanmayshukla60-netizen")');

fs.writeFileSync('backend/src/coral/fetchRealData.js', f);
console.log('fetchRealData patched.');
