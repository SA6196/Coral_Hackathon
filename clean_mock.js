const fs = require('fs');

const cleanFile = (filePath, key) => {
  if (!fs.existsSync(filePath)) return;
  const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const filtered = content.filter(item => {
    const val = item[key];
    if (typeof val === 'string') {
      const lower = val.toLowerCase();
      if (lower.includes('tanmay') || lower.includes('shukla')) {
        return false;
      }
    }
    return true;
  });
  
  // also specifically change any remaining back to contractor_x if I erroneously changed contractor_x to tanmayshukla60-netizen earlier
  const reverted = filtered.map(item => {
    if (item[key] === 'tanmayshukla60-netizen') {
      item[key] = 'contractor_x';
    }
    return item;
  });
  
  fs.writeFileSync(filePath, JSON.stringify(reverted, null, 2));
};

cleanFile('backend/mock-data/github.json', 'author');
cleanFile('backend/mock-data/slack.json', 'user');

console.log('Cleaned mock data files successfully.');
