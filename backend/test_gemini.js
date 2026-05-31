const axios = require('axios');
const inc = {
  incident_id: 'CORAL-1',
  maliciousCode: [{description: 'eval backdoor', preview: 'eval(req.body.cmd)'}],
  package_details: {package_name: 'metrics-engine'},
  pr_details: {developer: 'tanmayshukla60-netizen'}
};
const systemPrompt = 'Generate a summary of the incident';
axios.post('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=AIzaSyBdcgrSFUkZdWL05h52Hu_5JeXuASNAUlQ', {
  contents: [{parts: [{text: `Investigate incident CORAL-1 with full forensic details below:\n\n${JSON.stringify(inc, null, 2)}`}]}],
  systemInstruction: {parts: [{text: systemPrompt}]},
  generationConfig: {temperature: 0.2, maxOutputTokens: 1000},
  safetySettings: [
    {category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE'},
    {category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE'},
    {category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE'},
    {category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE'}
  ]
}).then(r => console.log(JSON.stringify(r.data, null, 2))).catch(e => console.error(e.response?.data || e.message));
