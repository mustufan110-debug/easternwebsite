// ==========  UNIVERSAL CAPTCHA + AJAX SUBMIT (3 FORMS)  ==========
(function () {
    /* 1. CAPTCHA fetcher */
    function fetchCaptcha(id) {
        fetch('get_captcha.php') // Fetches the CAPTCHA from your new PHP file
            .then(response => response.json())
            .then(data => {
                if (data.captcha) {
                    document.getElementById(id).textContent = data.captcha;
                }
            })
            .catch(error => {
                console.error('Error fetching CAPTCHA:', error);
                document.getElementById(id).textContent = 'Error';
            });
    }

    /* 2. Form AJAX submitter */
    // This function now sends the form data to the server for validation.
    function submitFormAjax(form) {
        const fd = new FormData(form);
        const btn = form.querySelector('button[type="submit"]');
        const originalButtonText = btn.textContent;
        btn.textContent = 'Sending…';
        btn.disabled = true;

        fetch('process_form1.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    showNotification(d.message || 'Submitted successfully!', 'success');
                    form.reset();
                } else {
                    showNotification(d.message || 'Submission failed. Please try again.', 'error');
                }
                // Fetch a new CAPTCHA for all forms after every submission attempt
                ['captcha1', 'captcha2', 'captcha3'].forEach(fetchCaptcha);
            })
            .catch(() => showNotification('❌ Network error. Try again.', 'error'))
            .finally(() => {
                btn.textContent = originalButtonText;
                btn.disabled = false;
            });

        return false; // Prevent default form submission as a fallback
    }

    /* 3. Notification helper (same as before) */
    function showNotification(msg, type = 'success') {
        const n = document.createElement('div');
        n.textContent = msg;
        n.style.cssText =
            `position:fixed;top:20px;right:20px;padding:12px 18px;border-radius:4px;color:#fff;font-weight:600;z-index:10000;${type === 'success' ? 'background:#28a745' : 'background:#dc3545'}`;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 4000);
    }

    /* 4. Initialise */
    document.addEventListener('DOMContentLoaded', () => {
        // Fetch initial CAPTCHA for all forms on page load
        ['captcha1', 'captcha2', 'captcha3'].forEach(fetchCaptcha);

        // Attach refresh listeners to all refresh buttons
        [1, 2, 3].forEach(i => {
            const btn = document.getElementById(`refresh-captcha${i}`);
            if (btn) btn.onclick = () => fetchCaptcha(`captcha${i}`);
        });

        // Attach submit handlers to all forms
        ['quoteForm', 'contactForm', 'careerForm'].forEach(id => {
            const f = document.getElementById(id);
            if (f) {
                f.onsubmit = (e) => {
                    e.preventDefault(); // Prevent the default browser submission
                    submitFormAjax(f);   // Handle submission with our AJAX function
                };
            }
        });
    });
})();