// Wait until the entire page is loaded
document.addEventListener('DOMContentLoaded', function() {

  // Find all elements that are dropdowns
  const dropdowns = document.querySelectorAll('.nav-item.dropdown');

  // Loop through each dropdown
  dropdowns.forEach(function(dropdown) {
    
    // Find the link that the user will click on
    const toggleLink = dropdown.querySelector('.nav-link');

    // Add a 'click' event listener to that link
    toggleLink.addEventListener('click', function(event) {
      
      // IMPORTANT: Prevent the link from trying to navigate to a new page
      event.preventDefault();

      // Check if the clicked dropdown is already open
      const isAlreadyOpen = dropdown.classList.contains('open');

      // First, close all other dropdowns to avoid having multiple menus open
      document.querySelectorAll('.nav-item.dropdown').forEach(function(d) {
        d.classList.remove('open');
      });

      // If the clicked dropdown was NOT already open, then open it
      if (!isAlreadyOpen) {
        dropdown.classList.add('open');
      }
    });
  });

  // Optional: Close dropdowns if the user clicks anywhere else on the page
  document.addEventListener('click', function(event) {
    if (!event.target.closest('.nav-item.dropdown')) {
      document.querySelectorAll('.nav-item.dropdown').forEach(function(dropdown) {
        dropdown.classList.remove('open');
      });
    }
  });
});