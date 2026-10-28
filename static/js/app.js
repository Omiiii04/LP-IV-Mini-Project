/**
 * Digital Forensics Toolkit · Core Client JavaScript
 * Lightweight, vanilla-JS, zero CDN dependencies, strict CSP compatible (zero inline scripts).
 */

(function () {
  'use strict';

  // 1. Toast Notification System
  window.ForensicToast = {
    show: function (message, type = 'info', duration = 4000) {
      let container = document.getElementById('forensicToastContainer');
      if (!container) {
        container = document.createElement('div');
        container.id = 'forensicToastContainer';
        container.className = 'toast-container';
        container.setAttribute('aria-live', 'polite');
        document.body.appendChild(container);
      }

      const toast = document.createElement('div');
      toast.className = `forensic-toast toast-${type}`;
      toast.innerHTML = `
        <div style="flex: 1;">${message}</div>
        <button type="button" aria-label="Dismiss alert" class="toast-dismiss-btn" data-dismiss-toast style="background:none;border:none;cursor:pointer;color:var(--ink-muted);font-size:1.1rem;line-height:1;">&times;</button>
      `;
      container.appendChild(toast);

      if (duration > 0) {
        setTimeout(() => {
          if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(8px)';
            setTimeout(() => toast.remove(), 160);
          }
        }, duration);
      }
    }
  };

  // Toast Dismissal Listener
  document.addEventListener('click', function (e) {
    const dismissBtn = e.target.closest('[data-dismiss-toast]');
    if (dismissBtn) {
      const toast = dismissBtn.closest('.forensic-toast');
      if (toast) toast.remove();
    }
  });

  // 2. Hash Click-to-Copy
  document.addEventListener('click', function (e) {
    const copyBtn = e.target.closest('[data-copy-hash]');
    if (copyBtn) {
      const hash = copyBtn.getAttribute('data-copy-hash');
      if (hash && navigator.clipboard) {
        navigator.clipboard.writeText(hash).then(() => {
          window.ForensicToast.show(`Copied hash to clipboard: ${hash.slice(0, 8)}...${hash.slice(-8)}`, 'success', 2500);
        }).catch(() => {
          window.ForensicToast.show('Clipboard permission denied', 'error');
        });
      }
    }
  });

  // 3. Auto-Submit on Select Change
  document.addEventListener('change', function (e) {
    if (e.target.matches('[data-auto-submit]')) {
      if (e.target.form) {
        e.target.form.submit();
      }
    }
  });

  // 4. Print Page Button
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-print-page]')) {
      window.print();
    }
  });

  // 5. Modal System (Accessible & zero external JS)
  window.ForensicModal = {
    open: function (modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if (focusable) focusable.focus();
      }
    },
    close: function (modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
      }
    }
  };

  // Close modal when clicking on overlay background or data-close-modal
  document.addEventListener('click', function (e) {
    if (e.target.hasAttribute('data-close-modal') || e.target.classList.contains('modal-overlay')) {
      const modal = e.target.closest('.modal-overlay');
      if (modal) {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
      }
    }
  });

  // Close modal on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      const openModal = document.querySelector('.modal-overlay.open');
      if (openModal) {
        openModal.classList.remove('open');
        openModal.setAttribute('aria-hidden', 'true');
      }
    }
  });

  // 6. Preview Modal Tab Switching (Data Attribute Handler)
  document.addEventListener('click', function (e) {
    const tabBtn = e.target.closest('[data-preview-tab]');
    if (tabBtn) {
      const tab = tabBtn.getAttribute('data-preview-tab');
      const hexBtn = document.getElementById('tabHexBtn');
      const textBtn = document.getElementById('tabTextBtn');
      const hexPanel = document.getElementById('previewHexDump');
      const textPanel = document.getElementById('previewTextContent');

      if (tab === 'hex') {
        if (hexBtn) { hexBtn.className = 'btn btn-sm btn-primary'; }
        if (textBtn) { textBtn.className = 'btn btn-sm btn-secondary'; }
        if (hexPanel) hexPanel.style.display = 'block';
        if (textPanel) textPanel.style.display = 'none';
      } else {
        if (hexBtn) { hexBtn.className = 'btn btn-sm btn-secondary'; }
        if (textBtn) { textBtn.className = 'btn btn-sm btn-primary'; }
        if (hexPanel) hexPanel.style.display = 'none';
        if (textPanel) textPanel.style.display = 'block';
      }
    }
  });

  // 7. Inline Evidence Integrity Verification
  window.verifyEvidence = function (evidenceId, csrfToken, btn) {
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = 'Verifying...';

    fetch(`/evidence/${evidenceId}/verify`, {
      method: 'POST',
      headers: {
        'X-CSRFToken': csrfToken,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    })
    .then(async (res) => {
      const data = await res.json();
      return { status: res.status, data };
    })
    .then((result) => {
      btn.disabled = false;
      btn.innerHTML = origHtml;

      const badge = document.getElementById(`status-badge-${evidenceId}`);
      if (result.status === 200) {
        if (badge) {
          badge.className = 'badge-forensic badge-verified';
          badge.innerHTML = '<span class="badge-shape">✓</span> Verified';
        }
        window.ForensicToast.show('✓ Integrity Confirmed: SHA-256 matches registered baseline.', 'success', 3500);
      } else {
        if (badge) {
          badge.className = 'badge-forensic badge-failed';
          badge.innerHTML = '<span class="badge-shape">✕</span> Tampered';
        }
        window.ForensicToast.show('⚠ Integrity Violation! Computed digest differs from registered baseline.', 'error', 6000);
      }
    })
    .catch(() => {
      btn.disabled = false;
      btn.innerHTML = origHtml;
      window.ForensicToast.show('Verification request failed or timed out.', 'error');
    });
  };

  // 8. Artifact Hex & Text Preview Modal
  window.openArtifactPreview = function (evidenceId) {
    window.ForensicModal.open('artifactPreviewModal');
    const titleEl = document.getElementById('previewModalFilename');
    const metaEl = document.getElementById('previewModalMeta');
    const hexContainer = document.getElementById('previewHexDump');
    const textContainer = document.getElementById('previewTextContent');

    if (titleEl) titleEl.textContent = `Inspecting Evidence #${evidenceId}`;
    if (metaEl) metaEl.textContent = 'Reading artifact bytes from storage...';
    if (hexContainer) hexContainer.innerHTML = '<div style="color:var(--ink-muted);padding:12px;">Loading hex dump...</div>';
    if (textContainer) textContainer.textContent = 'Loading text view...';

    fetch(`/evidence/${evidenceId}/preview`, {
      headers: { 'Accept': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
      if (titleEl) titleEl.textContent = data.filename || `Artifact #${evidenceId}`;
      if (metaEl) {
        metaEl.textContent = `Size: ${data.total_size} bytes · Preview: ${data.preview_bytes} bytes · SHA-256: ${data.sha256}`;
      }

      // Populate Hex View
      if (hexContainer && data.hex_lines) {
        let html = '<div style="display:flex; flex-direction:column; gap:2px;">';
        data.hex_lines.forEach(line => {
          html += `
            <div style="display:grid; grid-template-columns: 80px 1fr 140px; gap:12px; font-family:var(--font-mono); font-size:0.75rem;">
              <span style="color:var(--ink-muted);">${line.offset}</span>
              <span style="color:var(--ink-primary);">${line.hex}</span>
              <span style="color:var(--ink-secondary);">${line.ascii}</span>
            </div>
          `;
        });
        html += '</div>';
        hexContainer.innerHTML = html;
      }

      // Populate Text View
      if (textContainer) {
        if (data.is_text) {
          textContainer.textContent = data.text_preview;
        } else {
          textContainer.textContent = '[Binary data detected — inspect via Hex View]';
        }
      }
    })
    .catch(() => {
      if (metaEl) metaEl.textContent = 'Error loading artifact inspection bytes.';
    });
  };

  // 9. In-Page Log Severity Filter
  document.addEventListener('click', function (e) {
    const sevBtn = e.target.closest('[data-filter-sev]');
    if (sevBtn) {
      const container = sevBtn.closest('[data-log-filters]');
      if (!container) return;
      const analysisId = container.getAttribute('data-log-filters');
      const sev = sevBtn.getAttribute('data-filter-sev');

      // Update button active states
      container.querySelectorAll('[data-filter-sev]').forEach(btn => {
        btn.className = (btn === sevBtn) ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
      });

      // Filter rows
      const pane = document.getElementById(`events-list-${analysisId}`);
      if (pane) {
        const rows = pane.querySelectorAll('.log-line-row');
        rows.forEach(r => {
          const rowSev = r.getAttribute('data-severity');
          if (sev === 'ALL' || rowSev === sev) {
            r.style.display = 'flex';
          } else {
            r.style.display = 'none';
          }
        });
      }
    }
  });

  // 10. Drag-and-Drop Zone Enhancements
  document.querySelectorAll('[data-dropzone]').forEach(zone => {
    const input = zone.querySelector('input[type="file"]');
    if (!input) return;

    ['dragenter', 'dragover'].forEach(eventName => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove('dragover');
      }, false);
    });

    zone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length) {
        input.files = files;
        const submitBtn = zone.querySelector('button[type="submit"]');
        if (submitBtn) {
          submitBtn.textContent = `Upload & Analyze ${files[0].name}`;
        }
      }
    }, false);

    input.addEventListener('change', () => {
      if (input.files.length) {
        const submitBtn = zone.querySelector('button[type="submit"]');
        if (submitBtn) {
          submitBtn.textContent = `Upload & Analyze ${input.files[0].name}`;
        }
      }
    });
  });

  // 11. Keyboard Shortcuts (/ = search filter, g c = cases, g e = evidence, g d = dashboard)
  let keySequence = '';
  let keyTimer = null;

  document.addEventListener('keydown', function (e) {
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
      return;
    }

    if (e.key === '/') {
      e.preventDefault();
      const searchBox = document.querySelector('input[type="search"], input[name="q"], input[name="keyword"]');
      if (searchBox) searchBox.focus();
      return;
    }

    keySequence += e.key.toLowerCase();
    clearTimeout(keyTimer);
    keyTimer = setTimeout(() => { keySequence = ''; }, 600);

    if (keySequence === 'gc') {
      keySequence = '';
      window.location.href = '/cases';
    } else if (keySequence === 'ge') {
      keySequence = '';
      window.location.href = '/evidence';
    } else if (keySequence === 'gd') {
      keySequence = '';
      window.location.href = '/';
    } else if (keySequence === 'gl') {
      keySequence = '';
      window.location.href = '/logs';
    } else if (keySequence === 'gi') {
      keySequence = '';
      window.location.href = '/disk-images';
    }
  });

})();
