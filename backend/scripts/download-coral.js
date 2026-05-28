const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const binDir = path.join(__dirname, '../../coral_bin');
if (!fs.existsSync(binDir)) {
  fs.mkdirSync(binDir, { recursive: true });
}

let platform = os.platform();
let arch = os.arch();
let downloadUrl = '';
let exeName = 'coral';

if (platform === 'win32') {
  downloadUrl = 'https://coral-cli-releases.s3.amazonaws.com/coral-windows-amd64.exe';
  exeName = 'coral.exe';
} else if (platform === 'darwin') {
  downloadUrl = arch === 'arm64' 
    ? 'https://coral-cli-releases.s3.amazonaws.com/coral-darwin-arm64'
    : 'https://coral-cli-releases.s3.amazonaws.com/coral-darwin-amd64';
} else {
  // Assume Linux for Railway
  downloadUrl = arch === 'arm64'
    ? 'https://coral-cli-releases.s3.amazonaws.com/coral-linux-arm64'
    : 'https://coral-cli-releases.s3.amazonaws.com/coral-linux-amd64';
}

const destPath = path.join(binDir, exeName);

if (fs.existsSync(destPath)) {
  console.log(`✅ Coral CLI already exists at ${destPath}`);
  process.exit(0);
}

console.log(`⬇️  Downloading Coral CLI from ${downloadUrl}...`);

const file = fs.createWriteStream(destPath);
https.get(downloadUrl, (response) => {
  if (response.statusCode !== 200) {
    console.error(`Failed to download Coral CLI. HTTP Status: ${response.statusCode}`);
    try { fs.unlinkSync(destPath); } catch (e) {}
    process.exit(0);
  }

  response.pipe(file);
  file.on('finish', () => {
    file.close();
    console.log('✅ Coral CLI downloaded successfully.');
    if (platform !== 'win32') {
      console.log('Setting executable permissions...');
      execSync(`chmod +x "${destPath}"`);
    }
  });
}).on('error', (err) => {
  fs.unlinkSync(destPath);
  console.error(`Error downloading Coral CLI: ${err.message}`);
  // Don't crash the build if the download fails
  process.exit(0);
});
