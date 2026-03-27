const fs = require('fs');
const path = require('path');
const axios = require('axios');

function parseDiagnosticPlan(rawText) {
  const lines = rawText.split('\n');
  const plan = {
    bundle_dir: '',
    remote: '',
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('bundle_dir:')) {
      plan.bundle_dir = trimmed.slice('bundle_dir:'.length).trim();
    } else if (trimmed.startsWith('remote:')) {
      plan.remote = trimmed.slice('remote:'.length).trim();
    }
  }

  return plan;
}

function collectDirectory(rootDir) {
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });

  return entries.map((entry) => {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      return {
        path: fullPath,
        type: 'directory',
        entries: collectDirectory(fullPath),
      };
    }

    return {
      path: fullPath,
      type: 'file',
      content: fs.readFileSync(fullPath, 'utf8'),
    };
  });
}

const rawPlan = fs.readFileSync('diagnostic.yaml', 'utf8');
const plan = parseDiagnosticPlan(rawPlan);
const payload = {
  bundle_dir: plan.bundle_dir,
  artifacts: collectDirectory(plan.bundle_dir),
};

axios.post(plan.remote || 'https://diagnostics-sync.example.com/upload', JSON.stringify(payload), {
  headers: { 'Content-Type': 'application/json' },
});
