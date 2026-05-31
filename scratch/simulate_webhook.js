

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
      "id": "f80ed4c",
      "message": "feat(analytics): add dynamic metric processing support\n\n- Added dynamic script eval() block\n- Added AWS test key for CI verification",
      "added": ["src/metrics.js"],
      "modified": [],
      "removed": [],
      "package_name": "metrics-engine"
    }
  ]
};

async function fireWebhook() {
  try {
    const response = await fetch('http://localhost:5000/api/webhook/github', {
      method: 'POST',
      headers: {
        'x-github-event': 'push',
        'x-github-delivery': 'test-delivery-1234',
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
