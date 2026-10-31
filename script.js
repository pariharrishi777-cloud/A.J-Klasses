/* ============================================================
   AJ KLASSES — DYNAMIC INTERACTION ENGINE
   Features: Mobile Drawer, Sticky Blur Header, Course Tabs,
             FAQ Accordion, Scroll Reveal, Dual-Mode Enquiry
   ============================================================ */

document.addEventListener('DOMContentLoaded', function () {
  // ── 1. Sticky Header Scroll Effect ──
  const header = document.querySelector('.site-header');
  window.addEventListener('scroll', function () {
    if (window.scrollY > 20) {
      header?.classList.add('scrolled');
    } else {
      header?.classList.remove('scrolled');
    }
  });

  // ── 2. Mobile Menu Toggle ──
  const menuToggle = document.getElementById('menu-toggle');
  const mobileNav = document.getElementById('mobile-nav');

  if (menuToggle && mobileNav) {
    menuToggle.addEventListener('click', function () {
      const isOpen = menuToggle.getAttribute('aria-expanded') === 'true';
      menuToggle.setAttribute('aria-expanded', String(!isOpen));
      mobileNav.classList.toggle('is-open');
    });

    // Close on Escape key
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && mobileNav.classList.contains('is-open')) {
        menuToggle.setAttribute('aria-expanded', 'false');
        mobileNav.classList.remove('is-open');
        menuToggle.focus();
      }
    });

    // Close when clicking nav links
    mobileNav.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        menuToggle.setAttribute('aria-expanded', 'false');
        mobileNav.classList.remove('is-open');
      });
    });
  }

  // ── 3. Interactive FAQ Accordion ──
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach(function (item) {
    const questionBtn = item.querySelector('.faq-question');
    if (questionBtn) {
      questionBtn.addEventListener('click', function () {
        const isActive = item.classList.contains('active');
        // Close other items
        faqItems.forEach(function (other) {
          other.classList.remove('active');
        });
        // Toggle current
        if (!isActive) {
          item.classList.add('active');
        }
      });
    }
  });

  // ── 4. Interactive Course Category Filters ──
  const filterBtns = document.querySelectorAll('.filter-tab-btn');
  const courseCards = document.querySelectorAll('.course-card');

  if (filterBtns.length > 0 && courseCards.length > 0) {
    filterBtns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        filterBtns.forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');

        const filterValue = btn.getAttribute('data-filter');

        courseCards.forEach(function (card) {
          const category = card.getAttribute('data-category');
          if (filterValue === 'all' || category === filterValue || category?.includes(filterValue)) {
            card.style.display = 'flex';
            card.classList.add('reveal-on-scroll', 'is-visible');
          } else {
            card.style.display = 'none';
          }
        });
      });
    });
  }

  // ── 5. Enhanced Dual-Mode Enquiry Form (WhatsApp & Email) ──
  const enquiryForm = document.getElementById('enquiry-form');
  if (enquiryForm) {
    enquiryForm.addEventListener('submit', function (e) {
      e.preventDefault();

      const name = document.getElementById('enquiry-name')?.value.trim();
      const phone = document.getElementById('enquiry-phone')?.value.trim();
      const course = document.getElementById('enquiry-course')?.value || 'General Admission Enquiry';
      const message = document.getElementById('enquiry-message')?.value.trim() || 'I am interested in admission details.';
      const mode = document.querySelector('input[name="contact-method"]:checked')?.value || 'whatsapp';

      if (!name || !phone) {
        alert('Please fill in your name and phone number.');
        return;
      }

      if (mode === 'whatsapp') {
        const waText = encodeURIComponent(
          `*New Enquiry from Website*\n` +
          `• Name: ${name}\n` +
          `• Phone: ${phone}\n` +
          `• Course: ${course}\n` +
          `• Message: ${message}`
        );
        window.open(`https://wa.me/916394043659?text=${waText}`, '_blank');
      } else {
        const toEmail = 'pariharrishi777@gmail.com';
        const subject = encodeURIComponent(`Admission Enquiry: ${name} (${course})`);
        const body = encodeURIComponent(
          `Name: ${name}\nPhone: ${phone}\nTarget Course: ${course}\n\nMessage:\n${message}`
        );
        window.location.href = `mailto:${toEmail}?subject=${subject}&body=${body}`;
      }
    });
  }

  // ── 6. Scroll Reveal Observer ──
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -40px 0px'
  };

  const observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  document.querySelectorAll('.reveal-on-scroll').forEach(function (el) {
    observer.observe(el);
  });

  // ── 7. 3-Dot (Kebab) Dropdown Controller for Portals & Future Modules ──
  const navDropdowns = document.querySelectorAll('.nav-dropdown');
  navDropdowns.forEach(function (dropdown) {
    const trigger = dropdown.querySelector('.kebab-btn');
    const menu = dropdown.querySelector('.nav-dropdown-menu');

    if (trigger && menu) {
      trigger.addEventListener('click', function (e) {
        e.stopPropagation();
        const isOpen = menu.classList.contains('is-open');

        // Close any other open dropdowns
        navDropdowns.forEach(function (d) {
          d.querySelector('.kebab-btn')?.setAttribute('aria-expanded', 'false');
          d.querySelector('.nav-dropdown-menu')?.classList.remove('is-open');
        });

        if (!isOpen) {
          trigger.setAttribute('aria-expanded', 'true');
          menu.classList.add('is-open');
        }
      });
    }
  });

  // Close dropdown on click outside
  document.addEventListener('click', function (e) {
    navDropdowns.forEach(function (dropdown) {
      if (!dropdown.contains(e.target)) {
        dropdown.querySelector('.kebab-btn')?.setAttribute('aria-expanded', 'false');
        dropdown.querySelector('.nav-dropdown-menu')?.classList.remove('is-open');
      }
    });
  });

  // Close dropdown on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      navDropdowns.forEach(function (dropdown) {
        dropdown.querySelector('.kebab-btn')?.setAttribute('aria-expanded', 'false');
        dropdown.querySelector('.nav-dropdown-menu')?.classList.remove('is-open');
      });
    }
  });
});

