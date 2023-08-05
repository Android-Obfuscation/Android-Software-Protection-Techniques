---
layout: default
title: Home
nav_order: 1
description: ""
permalink: /
---

<button class="btn js-toggle-dark-mode">Dark color scheme</button>

<script>
const toggleDarkMode = document.querySelector('.js-toggle-dark-mode');

jtd.addEvent(toggleDarkMode, 'click', function(){
  if (jtd.getTheme() === 'dark') {
    jtd.setTheme('light');
    toggleDarkMode.textContent = 'Dark color scheme';
  } else {
    jtd.setTheme('dark');
    toggleDarkMode.textContent = 'Light color scheme';
  }
});
</script>

This website is a supporting material from the paper *Android Software Protection in the Wild: A Survey*. Here the authors are trying to encourage analysts to learn about Software Protection Techniques used in the wild for Android applications, as well as for uploading newer techniques, and code snippets that document these techniques.

Most of the current techniques here present are from public repositories, or collected from other resources added as references. In those cases where Reverse Engineering was applied, it was in samples from websites like [Koodous](https://koodous.com/), and no name of protection is given. Together with that, the code snippets presented are anonymized in the case, some name could be recognized since the purpose of this research is not beyond understanding what are the current techniques used to protect software.

This webpage does not allow uploading bypassing techniques for the presented software protection techniques, again the purpose is understanding the state of the art on Android Software Protection.

## References

* "Surreptitious Software: Obfuscation, Watermarking and Tampering For Software Protection" by Christian Collberg and Jasvir Nagra.
* [OWASP MASTG](https://mas.owasp.org/MASTG/) by the OWASP Mobile Application Security (MAS) Project.

<img src="/assets/images/logo.png" alt="Android Software Protection Techniques" width="500" height="600" style="vertical-align:bottom;text-align: center;">
