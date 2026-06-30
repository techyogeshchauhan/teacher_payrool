"""Add CSRF tokens to all POST forms in templates."""
import os
import re

CSRF_TOKEN = '\n        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">'

templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
count = 0

for root, dirs, files in os.walk(templates_dir):
    for fname in files:
        if not fname.endswith('.html'):
            continue
        fpath = os.path.join(root, fname)
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'csrf_token' in content:
            continue  # Already has CSRF token
        
        # Find all POST form tags and inject CSRF token after opening tag
        pattern = r'(<form[^>]*method="POST"[^>]*>)'
        matches = re.findall(pattern, content, re.IGNORECASE)
        
        if matches:
            new_content = re.sub(pattern, r'\1' + CSRF_TOKEN, content, flags=re.IGNORECASE)
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            count += len(matches)
            print(f'  CSRF added to {fname} ({len(matches)} forms)')

print(f'\nTotal: {count} forms updated with CSRF tokens')
