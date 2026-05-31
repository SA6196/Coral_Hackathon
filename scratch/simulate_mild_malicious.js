const payload = {
  ref: "refs/heads/main",
  repository: {
    full_name: "your-org/your-repo"
  },
  pusher: {
    name: "contractor_x"
  },
  commits: [
    {
      "id": "e7b9a2d",
      "message": "fix(ui): remove hidden zero-width space in title component\n\nThere was a weird \u200B character here.",
      "added": [],
      "modified": ["src/components/Title.js"],
      "removed": [],
      "package_name": "lodash"
    }
  ]
};

async function fireWebhook() {
  try {
    const response = await fetch('http://localhost:5000/api/webhook/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'push',
        'x-github-delivery': 'test-delivery-mild-malicious',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    console.log("Webhook fired successfully!", data);
  } catch (error) {
    console.error("Failed to fire webhook:", error.message);
  }
}

fireWebhook();
