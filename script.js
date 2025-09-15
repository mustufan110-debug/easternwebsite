// ========================================
// NEW MOBILE MENU SYSTEM
// ========================================

// Mobile Menu Elements
const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
const mobileMenuOverlay = document.querySelector('.mobile-menu-overlay');
const mobileMenuClose = document.querySelector('.mobile-menu-close');
const mobileSubmenuToggles = document.querySelectorAll('.mobile-submenu-toggle');
const mobileMenuLinks = document.querySelectorAll('.mobile-menu-link');

// Toggle Mobile Menu
function toggleMobileMenu() {
    mobileMenuToggle.classList.toggle('active');
    mobileMenuOverlay.classList.toggle('active');
    document.body.style.overflow = mobileMenuOverlay.classList.contains('active') ? 'hidden' : 'auto';
}

// Close Mobile Menu
function closeMobileMenu() {
    mobileMenuToggle.classList.remove('active');
    mobileMenuOverlay.classList.remove('active');
    document.body.style.overflow = 'auto';
    
    // Close all submenus
    document.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.classList.remove('active');
    });
}

// Toggle Mobile Submenu
function toggleMobileSubmenu(e) {
    e.preventDefault();
    const menuItem = e.currentTarget.closest('.mobile-menu-item');
    const isActive = menuItem.classList.contains('active');
    
    // Close all other submenus
    document.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Toggle current submenu
    if (!isActive) {
        menuItem.classList.add('active');
    }
}

// Event Listeners
if (mobileMenuToggle) {
    mobileMenuToggle.addEventListener('click', toggleMobileMenu);
}

if (mobileMenuClose) {
    mobileMenuClose.addEventListener('click', closeMobileMenu);
}

if (mobileMenuOverlay) {
    mobileMenuOverlay.addEventListener('click', function(e) {
        if (e.target === mobileMenuOverlay) {
            closeMobileMenu();
        }
    });
}

// Submenu toggles
mobileSubmenuToggles.forEach(toggle => {
    toggle.addEventListener('click', toggleMobileSubmenu);
});

// Close menu when clicking on regular menu links
mobileMenuLinks.forEach(link => {
    if (!link.classList.contains('mobile-submenu-toggle')) {
        link.addEventListener('click', closeMobileMenu);
    }
});

// Close menu on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && mobileMenuOverlay.classList.contains('active')) {
        closeMobileMenu();
    }
});

// Handle window resize
window.addEventListener('resize', function() {
    if (window.innerWidth > 991 && mobileMenuOverlay.classList.contains('active')) {
        closeMobileMenu();
    }
});
window.addEventListener('scroll',()=>{const header=document.querySelector('.header');if(window.scrollY>100){header.style.background='rgba(255, 255, 255, 0.98)';header.style.boxShadow='0 2px 20px rgba(0, 0, 0, 0.1)'}else{header.style.background='white';header.style.boxShadow='0 2px 10px rgba(0, 0, 0, 0.1)'}});document.querySelectorAll('a[href^="#"]').forEach(anchor=>{anchor.addEventListener('click',function(e){e.preventDefault();const target=document.querySelector(this.getAttribute('href'));if(target){target.scrollIntoView({behavior:'smooth',block:'start'})}})});const languageSelector=document.querySelector('.language-selector');const languageModal=document.getElementById('languageModal');const closeModal=document.querySelector('.close-modal');const languageOptions=document.querySelectorAll('.language-option');languageSelector.addEventListener('click',()=>{languageModal.style.display='block';document.body.style.overflow='hidden'});closeModal.addEventListener('click',()=>{languageModal.style.display='none';document.body.style.overflow='auto'});window.addEventListener('click',(e)=>{if(e.target===languageModal){languageModal.style.display='none';document.body.style.overflow='auto'}});

// Language translations
const translations = {
    en: {
        // Navigation
        'HOME': 'HOME',
        'ABOUT US': 'ABOUT US',
        'MEMBERSHIPS': 'MEMBERSHIPS',
        'OUR SERVICES': 'OUR SERVICES',
        'MORE': 'MORE',
        'SPECIALIZED SERVICES': 'SPECIALIZED SERVICES',
        'Healthcare Logistics': 'Healthcare Logistics',
        'DG Shipments': 'DG Shipments',
        'Project Logistics': 'Project Logistics',
        'Our Team': 'Our Team',
        'Calculator': 'Calculator',
        'Our Offices': 'Our Offices',
        'Customer Reviews': 'Customer Reviews',
        'CONTACT US': 'CONTACT US',
        'Have any Questions?': 'Have any Questions?',
        'COMPANY_MAIN': 'EASTERN CARGO',
        'COMPANY_SUB': 'CARRIERS (I) PVT.LTD',
        'EMAIL_INFO': 'info@easterncargo.co.in',
        'EMAIL_LSETH': 'lseth@easterncargo.co.in',
        'PHONE_NO': '+91-22-67539999',
        'LANGUAGE_SELECTOR_TEXT': 'EN',
        
        // Hero Section
        'Worldwide Logistics': 'Worldwide Logistics',
        'International Air Freight': 'International Air Freight',
        'Contact Us': 'Contact Us',
        'Get your free quote today': 'Get your free quote today',
        'Reliable & Efficient': 'Reliable & Efficient',
        'Multimodal Transport Network': 'Multimodal Transport Network',
        'Our Services': 'Our Services',
        'Global Trade Solutions': 'Global Trade Solutions',
        'Ocean Freight Solutions': 'Ocean Freight Solutions',
        'Get a Quote': 'Get a Quote',
        'Select Service': 'Select Service',
        'Air Freight': 'Air Freight',
        'Sea Freight': 'Sea Freight',
        'Land Transport': 'Land Transport',
        'Warehousing': 'Warehousing',
        'Pharma Logistics': 'Pharma Logistics',
        'DGR Shipments': 'DGR Shipments',
        'Project Logistics': 'Project Logistics',
        'Name': 'Name',                                   
        'Email': 'Email',                                 
        'Phone': 'Phone',                               
        'Service Type': 'Service Type',                   
        'Your Message': 'Your Message',                  
        'Enter CAPTCHA': 'Enter CAPTCHA',                 
        'Request A Quote': 'Request A Quote',
        'WRONG_CAPTCHA': '❌ Wrong CAPTCHA',
        'CORRECT_CAPTCHA': '✅ CAPTCHA verified',

        
        //WHY CHOOSE US
        'WHY CHOOSE US': 'WHY CHOOSE US',
        'Delivering Comprehensive Global Logistics Solutions': 'Delivering Comprehensive Global Logistics Solutions.',
        'WHAT WE DO': 'WHAT WE DO',
        'OUR AWARD': 'OUR AWARD',
        'COMPANY HISTORY': 'COMPANY HISTORY',
        'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.',
        'Warehouse Facility': 'Warehouse Facility',
        'Air Freight Facility': 'Air Freight Facility',
        'Cost Effective Pricing': 'Cost Effective Pricing',
        'Timely Delivery': 'Timely Delivery',
        'Container delivery': 'Container delivery',
        'Best Team Member': 'Best Team Member',
        'Learn More': 'Learn More',
        'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains.We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach..',
        'Global Network': 'Global Network',               
        'Real-time Tracking': 'Real-time Tracking',       
        'Customs Expertise': 'Customs Expertise',         
        'Multi-modal Transport': 'Multi-modal Transport', 
        'Risk Management': 'Risk Management', 
        'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.': 'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.',
        'ISO Certified': 'ISO Certified',
        'Industry Awards': 'Industry Awards',
        'Quality Standards': 'Quality Standards',
        'Customer Recognition': 'Customer Recognition',
        'AEO certified': 'AEO certified',
        'Excellence Certificates': 'Excellence Certificates',
        
        // Memberships
        'Memberships & Certifications': 'Memberships & Certifications',
        'Proud members of leading global logistics organizations': 'Proud members of leading global logistics organizations',
        'ISO 9001:2015': 'ISO 9001:2015',
        'AEO Certified': 'AEO Certified',
        'WCA Member': 'WCA Member',
        'IATA Agent': 'IATA Agent',
        'FIATA Member': 'FIATA Member',
        'ACAAI Member': 'ACAAI Member',
        'MIFFA Member': 'MIFFA Member',
        
        // About Section
        'About EASTERN CARGO CARRIERS (I) PVT.LTD': 'About EASTERN CARGO CARRIERS (I) PVT.LTD',
        'Our Legacy & Commitment': 'Our Legacy & Commitment',
        'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.': 'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.',
        'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.': 'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.',
        'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.': 'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.',
        'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.': 'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.',
        
        // Timeline
        'Ecc\'s Group Key Milestones in Aviation and Logistics': 'Ecc\'s Group Key Milestones in Aviation and Logistics',
        'YEAR_1979': '1979',
        'Custom House Agent': 'Custom House Agent',
        'Established as a CHA': 'Established as a CHA',
        'CHA_TITLE': 'Custom House Agent (CHA)',
        'CHA_DESC': 'Eastern Cargo Carriers began its journey as a Custom House Agent, providing essential customs clearance services for import and export operations. This marked the foundation of our logistics expertise.',
        'CHA_LIST_1': 'Customs clearance services',
        'CHA_LIST_2': 'Documentation handling',
        'CHA_LIST_3': 'Import/Export facilitation',
        'YEAR_1984': '1984',
        'IATA Agent': 'IATA Agent',
        'Leveraging accreditation': 'Leveraging accreditation',
        'IATA_TITLE': 'IATA Accreditation',
        'IATA_DESC': 'Achieved International Air Transport Association (IATA) accreditation, enabling us to provide comprehensive air freight services with global reach and industry-standard practices.',
        'IATA_LIST_1': 'Global air freight network',
        'IATA_LIST_2': 'IATA standard compliance',
        'IATA_LIST_3': 'International cargo operations',
        'YEAR_1989': '1989',
        'Charter Operation': 'Charter Operation',
        'Initiated first charter': 'Initiated first charter',
        'CHARTER_TITLE': 'Charter Operations Launch',
        'CHARTER_DESC': 'Launched our charter operations division, providing dedicated aircraft solutions for urgent and specialized cargo requirements. This expanded our service portfolio significantly.',
        'CHARTER_LIST_1': 'Dedicated aircraft charters',
        'CHARTER_LIST_2': 'Urgent cargo solutions',
        'CHARTER_LIST_3': 'Specialized transport services',
        'YEAR_1994': '1994-99',
        'Network Expansion': 'Network Expansion',
        'Achieved Pan-India presence': 'Achieved Pan-India presence',
        'NETWORK_TITLE': 'Pan-India Network Expansion',
        'NETWORK_DESC': 'Successfully expanded our operations across India, establishing a comprehensive network of offices and service centers to provide nationwide logistics solutions.',
        'NETWORK_LIST_1': 'Nationwide presence',
        'NETWORK_LIST_2': 'Multiple office locations',
        'NETWORK_LIST_3': 'Comprehensive service network',
        'YEAR_2005': '2005-11',
        'GSAs & Consolidation': 'GSAs & Consolidation',
        'Key GSA partnerships': 'Key GSA partnerships',
        'GSA_TITLE': 'GSA Partnerships & Consolidation',
        'GSA_DESC': 'Formed strategic General Sales Agent (GSA) partnerships with major international airlines and shipping lines, consolidating our position as a leading logistics provider.',
        'GSA_LIST_1': 'Strategic airline partnerships',
        'GSA_LIST_2': 'Global shipping alliances',
        'GSA_LIST_3': 'Enhanced service capabilities',
        'YEAR_2015': '2015-16',
        'Pharma Expertise': 'Pharma Expertise',
        'Specialized services': 'Specialized services',
        'PHARMA_TITLE': 'Pharmaceutical Logistics Expertise',
        'PHARMA_DESC': 'Developed specialized expertise in pharmaceutical logistics, including temperature-controlled transportation and GDP-compliant warehousing for life sciences products.',
        'PHARMA_LIST_1': 'Temperature-controlled solutions',
        'PHARMA_LIST_2': 'GDP-compliant warehousing',
        'PHARMA_LIST_3': 'Pharma-specific expertise',
        'YEAR_2017': '2017-18',
        'Temp Warehouse': 'Temp Warehouse',
        'Pharma packaging': 'Pharma packaging',
        'TEMP_WAREHOUSE_TITLE': 'Temperature-Controlled Warehouse',
        'TEMP_WAREHOUSE_DESC': 'Established dedicated temperature- controlled warehousing facilities for pharmaceutical products, ensuring proper storage and handling of sensitive cargo.',
        'TEMP_WAREHOUSE_LIST_1': 'Temperature-controlled storage',
        'TEMP_WAREHOUSE_LIST_2': 'Pharma packaging services',
        'TEMP_WAREHOUSE_LIST_3': 'Quality assurance protocols',
        'YEAR_2019': '2019-20',
        'Critical Response': 'Critical Response',
        'Imported life-saving drugs': 'Imported life-saving drugs',
        'CRITICAL_RESPONSE_TITLE': 'Critical Response Operations',
        'CRITICAL_RESPONSE_DESC': 'Successfully handled critical response operations during the pandemic, importing life-saving drugs and medical supplies with unprecedented speed and efficiency.',
        'CRITICAL_RESPONSE_LIST_1': 'Emergency medical supplies',
        'CRITICAL_RESPONSE_LIST_2': 'Rapid response logistics',
        'CRITICAL_RESPONSE_LIST_3': 'Life-saving drug transport',
        'YEAR_2020': '2020-21',
        'Governor\'s Award': 'Governor\'s Award',
        'For Pharma Exports': 'For Pharma Exports',
        'GOVERNOR_AWARD_TITLE': 'Governor\'s Award Recognition',
        'GOVERNOR_AWARD_DESC': 'Received the prestigious Governor\'s Award for excellence in pharmaceutical exports, recognizing our outstanding contribution to the healthcare logistics sector.',
        'GOVERNOR_AWARD_LIST_1': 'Excellence in pharma exports',
        'GOVERNOR_AWARD_LIST_2': 'Industry recognition',
        'GOVERNOR_AWARD_LIST_3': 'Healthcare logistics leadership',
        
        // Services
        'Wide variety of logistics services': 'Wide variety of logistics services',
        'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.': 'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.',
        'Air Freight (Export & Import)': 'Air Freight (Export & Import)',
        'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.': 'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.',
        'Ocean Freight (Import & Export)': 'Ocean Freight (Import & Export)',
        'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.': 'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.',
        'Customs Brokerage': 'Customs Brokerage',
        'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.': 'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.',
        'Warehouse & Distribution': 'Warehouse & Distribution',
        'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.': 'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.',
        'Air Charter': 'Air Charter',
        'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.': 'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.',
        'Your Pet Pal': 'Your Pet Pal',
        'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.': 'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.',
        'Express Logistics': 'Express Logistics',
        'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.': 'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.',
        'Unaccompanied Baggage Shipping': 'Unaccompanied Baggage Shipping',
        'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.': 'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.',

        // Customer Reviews
        'What our clients say': 'What our clients say',
        'Trusted experiences shared by our customers': 'Trusted experiences shared by our customers.',
        'Superfast Delivery': 'Superfast Delivery',
        'Eastern Cargo Carriers provided an excellent service for my shipment. From pickup to delivery, everything was seamless and on time. I truly appreciate their professionalism and customer support.': 'Eastern Cargo Carriers provided an excellent service for my shipment. From pickup to delivery, everything was seamless and on time. I truly appreciate their professionalism and customer support.',
        'Excellent Services': 'Excellent Services',
        'Very professional company with reliable services and no delays. Every shipment is handled smoothly and on time, giving me complete peace of mind. Truly one of the best choices for dependable cargo solutions.': 'Very professional company with reliable services and no delays. Every shipment is handled smoothly and on time, giving me complete peace of mind. Truly one of the best choices for dependable cargo solutions.',
        'Reliable Partner': 'Reliable Partner',
        'Eastern Cargo Carriers has become our trusted partner of choice. Their punctuality, professionalism, and reliability ensure every delivery is handled with care and always on time.': 'Eastern Cargo Carriers has become our trusted partner of choice. Their punctuality, professionalism, and reliability ensure every delivery is handled with care and always on time.',
        'Affordable & Safe': 'Affordable & Safe',
        'Eastern Cargo Carriers offers the most economical and safest way to send shipments from the UAE. Their punctuality, professionalism, and reliability make the whole process smooth and stress-free.': 'Eastern Cargo Carriers offers the most economical and safest way to send shipments from the UAE. Their punctuality, professionalism, and reliability make the whole process smooth and stress-free.',
        'Outstanding Support': 'Outstanding Support',
        'Eastern Cargo Carriers impressed me with their professional support team. They provided timely updates, handled every query with care, and ensured my shipment arrived punctually and without issues.': 'Eastern Cargo Carriers impressed me with their professional support team. They provided timely updates, handled every query with care, and ensured my shipment arrived punctually and without issues.',
        'Trusted for Years': 'Trusted for Years',
        'We’ve relied on Eastern Cargo Carriers for years, and their consistency in punctuality, professionalism, and reliable service has made them our first choice for every shipment.': 'We’ve relied on Eastern Cargo Carriers for years, and their consistency in punctuality, professionalism, and reliable service has made them our first choice for every shipment.',
        
        // Calculator
        'Smart Cargo Calculator': 'Smart Cargo Calculator',
        'Centimeters (CM)': 'Centimeters (CM)',
        'Inches (IN)': 'Inches (IN)',
        'Package Dimensions': 'Package Dimensions',
        '+ Add Package': '+ Add Package',
        'Reset': 'Reset',
        'Calculate': 'Calculate',
        
        // Career/Contact Forms
        'Join Our Team': 'Join Our Team',
        'Build your career with Eastern Cargo Carriers – explore exciting opportunities today.': 'Build your career with Eastern Cargo Carriers – explore exciting opportunities today.',
        'Upload Resume': 'Upload Resume',
        'Your Message (Optional)': 'Your Message (Optional)',
        'Submit Application': 'Submit Application',
        'Request your free logistics quote today and experience hassle-free shipping.': 'Request your free logistics quote today and experience hassle-free shipping.',
        
        // Footer
        'FOOTER_HEADING': 'Eastern Cargo Carriers (I) Pvt.Ltd.',
        'FOOTER_ADDRESS': 'Unit #25/26/27, Adarsh Industrial Estate, Sahar Road, Chakala, Andheri (East), Mumbai – 400 099',
        'Quick Links': 'Quick Links',
        'About Us': 'About Us',
        'Careers': 'Careers',
        'Get a Quote': 'Get a Quote',
        'Our Team': 'Our Team',
        'Our Services': 'Our Services',
        'Client Reviews': 'Client Reviews',
        'Specialized Services': 'Specialized Services',
        'Express Logistics': 'Express Logistics',
        'Healthcare Logistics': 'Healthcare Logistics',
        'DG Shipments': 'DG Shipments',
        'Project Logistics': 'Project Logistics',
        'Find Us': 'Find Us',
        'Follow us :': 'Follow us :',
        'COPYRIGHT': '© Copyright 2025. All Rights Reserved by Eastern Cargo Carriers (I) Pvt.Ltd',
        'Select Language': 'Select Language',
        'CLOSE_MODAL': '×',
        'English': 'English',
        'Spanish': 'Español',
        'French': 'Français',
        'German': 'German',
        'Chinese': '中文',
        'Japanese': '日本語',

        //Menu
        'ABOUT US': 'ABOUT US',
        'OUR SERVICES': 'OUR SERVICES',
        'MORE': 'MORE',
        'SPECIALIZED SERVICES': 'SPECIALIZED SERVICES',
        'Healthcare Logistics': 'Healthcare Logistics',
        'DG Shipments': 'DG Shipments',
        'Project Logistics': 'Project Logistics',
        'Our Team': 'Our Team',
        'Calculator': 'Calculator',
        'Customer Reviews': 'Customer Reviews',
        'CONTACT US': 'CONTACT US',
        'Have any Questions?': 'Have any Questions?',

        //Air Freight
        "Air Freight (Export & Import Services)": "Air Freight (Export & Import Services)",
        "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.": "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.",
        "Why Choose Our Air Freight Services?": "Why Choose Our Air Freight Services?",
        "Aggressive, Competitive Rates:": "Aggressive, Competitive Rates:",
        "Leverage our airline relationships for the best pricing to key global hubs.": "Leverage our airline relationships for the best pricing to key global hubs.",
        "Faster Transit Times:": "Faster Transit Times:",
        "Priority access ensures your cargo arrives on schedule—every time.": "Priority access ensures your cargo arrives on schedule—every time.",
        "Advanced Cold Chain & Temperature Control:": "Advanced Cold Chain & Temperature Control:",
        "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.": "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.",
        "Specialized Cargo Handling:": "Specialized Cargo Handling:",
        "From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.": "From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.",
        "End-to-End Service:": "End-to-End Service:",
        "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.": "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.",
        "Additional Capabilities": "Additional Capabilities",
        "Cargo consolidation for cost efficiency to key destinations.": "Cargo consolidation for cost efficiency to key destinations.",
        "Expert handling of personal effects, household goods, and chartered flight operations.": "Expert handling of personal effects, household goods, and chartered flight operations.",
        "Full spectrum of value-added services with and expert support at every step.": "Full spectrum of value-added services with and expert support at every step.",

        //OCEAN_FREIGHT
        "OCEAN_FREIGHT_TITLE": "Ocean Freight (Import & Export Services)",
        "OCEAN_FREIGHT_DESC": "The goodwill and strong partnerships we've cultivated with major shipping companies over the years enable us to deliver comprehensive ocean freight solutions that meet strict time constraints for both export and import operations. Our expertise spans the entire maritime logistics spectrum, from standard containerized shipments to complex project cargo, backed by excellent overseas agents who ensure seamless door-to-door delivery worldwide.",
        "WHY_CHOOSE_OCEAN_FREIGHT_TITLE": "Why Choose Our Ocean Freight Services?",
        "OCEAN_FREIGHT_FEATURE_1_TITLE": "Comprehensive FCL & LCL Solutions:",
        "OCEAN_FREIGHT_FEATURE_1_DESC": "Flexible booking options with competitive rates through our established shipping line partnerships for full and consolidated containers.",
        "OCEAN_FREIGHT_FEATURE_2_TITLE": "Specialized Cargo Expertise:",
        "OCEAN_FREIGHT_FEATURE_2_DESC": "Expert handling of ODC (odd dimension cargo), project cargo, hazardous materials, and reefer cargo with temperature-controlled solutions.",
        "OCEAN_FREIGHT_FEATURE_3_TITLE": "End-to-End Service Integration:",
        "OCEAN_FREIGHT_FEATURE_3_DESC": "Complete logistics management including customs clearance, packing, palletization, marine insurance, and DDU/DDP handling.",
        "OCEAN_FREIGHT_FEATURE_4_TITLE": "Global Network & Trade Lane Specialization:",
        "OCEAN_FREIGHT_FEATURE_4_DESC": "Extensive overseas agent network ensures reliable service across specialized trade routes with local expertise.",
        "OCEAN_FREIGHT_FEATURE_5_TITLE": "Value-Added Maritime Services:",
        "OCEAN_FREIGHT_FEATURE_5_DESC": "Comprehensive support including consolidation/deconsolidation, warehousing, distribution, transportation, and personal effects handling for complete supply chain management.",

        //CUSTOMS_BROKERAGE
        "CUSTOMS_BROKERAGE_TITLE": "Customs Brokerage Services",
        "CUSTOMS_BROKERAGE_DESC": "Navigating complex international trade regulations requires expert customs brokerage services that ensure swift, compliant clearance for your export shipments. As AEO-certified customs brokers with deep regulatory expertise, we streamline the entire customs process, minimize delays, and optimize duty costs for businesses across all industries.",
        "WHY_CHOOSE_CUSTOMS_BROKERAGE_TITLE": "Why Choose Our Customs Brokerage Services?",
        "CUSTOMS_BROKERAGE_FEATURE_1_TITLE": "AEO-Certified Expertise:",
        "CUSTOMS_BROKERAGE_FEATURE_1_DESC": "Authorized Economic Operator status ensures faster, trusted customs processing with reduced inspections.",
        "CUSTOMS_BROKERAGE_FEATURE_2_TITLE": "Complete Regulatory Compliance:",
        "CUSTOMS_BROKERAGE_FEATURE_2_DESC": "Full documentation management, tariff classification, and adherence to all import/export regulations.",
        "CUSTOMS_BROKERAGE_FEATURE_3_TITLE": "Duty & Cost Optimization:",
        "CUSTOMS_BROKERAGE_FEATURE_3_DESC": "Strategic tariff classification and trade agreement utilization to minimize customs duties and fees.",
        "CUSTOMS_BROKERAGE_FEATURE_4_TITLE": "Specialized Cargo Handling:",
        "CUSTOMS_BROKERAGE_FEATURE_4_DESC": "Expert clearance of hazardous materials, restricted goods, and high-value shipments with regulatory compliance.",
        "CUSTOMS_BROKERAGE_FEATURE_5_TITLE": "End-to-End Support:",
        "CUSTOMS_BROKERAGE_FEATURE_5_DESC": "Comprehensive service from documentation preparation to final delivery.",

        //WAREHOUSE
        "WAREHOUSE_TITLE": "Warehouse and Distribution Services",
        "WAREHOUSE_DESC": "At Eastern Cargo Carriers (I) Pvt.LTD , we ensure your supply chain operates seamlessly by providing both dedicated and shared warehousing and distribution services tailored to your needs. Our experienced associate team delivers robust support at every stage of transportation, efficiently managing your goods from storage to final delivery. Whether you require short-term or long-term storage, we offer secure, organized facilities equipped for palletizing, packing, shrink wrapping, and labelling. Our strategic warehousing network enables quick, reliable access to major trade routes, ensuring your products reach customers on time, every time. We also handle specialized requirements such as fumigation to maintain product safety standards and comply with international regulations.",

        //AIR_CHARTER
        "AIR_CHARTER_TITLE": "Air Charter Services",
        "AIR_CHARTER_DESC": "Since 1989, Eastern Cargo Carriers has specialized in urgent and comprehensive air cargo chartering for time-critical and specialized shipments. Our dedicated team is expertly trained to handle complex cargo—from life-saving pharmaceuticals during the pandemic to oversized industrial equipment—ensuring your freight is delivered with unmatched speed, security, and flexibility. We offer full and partial charter options, providing complete control over the transportation process, with end-to-end management including aircraft positioning, handling, customs coordination, and airport-to-airport delivery at all major Indian airports.",
        "WHY_CHOOSE_AIR_CHARTER_TITLE": "Why Choose Our Air Charter Services?",
        "AIR_CHARTER_FEATURE_1_TITLE": "Custom Charter Options:",
        "AIR_CHARTER_FEATURE_1_DESC": "Full or partial charters, one-way or round-trip, tailored to your schedule and cargo requirements.",
        "AIR_CHARTER_FEATURE_2_TITLE": "Emergency Logistics Expertise:",
        "AIR_CHARTER_FEATURE_2_DESC": "Proven track record executing critical missions—such as pandemic-related pharmaceutical export and imports—under stringent timelines.",
        "AIR_CHARTER_FEATURE_3_TITLE": "Comprehensive Handling:",
        "AIR_CHARTER_FEATURE_3_DESC": "Complete charter management from aircraft positioning to specialized loading, customs clearance, and delivery, in compliance with DGCA guidelines.",
        "AIR_CHARTER_FEATURE_4_TITLE": "Strategic Airport Access:",
        "AIR_CHARTER_FEATURE_4_DESC": "Operations at all major Indian customs airports, ensuring rapid turnaround and maximum reach.",

        //PET_PAL
        "PET_PAL_TITLE": "Your Pet Pal: Live Animal Transport",
        "PET_PAL_DESC": "Whether it’s your beloved cat or dog—or even horses and elephants—Eastern Cargo Carriers ensures every pet travels with the utmost care. Our specialized facilities, climate-controlled vehicles, and trained animal-handling team streamline inbound and outbound live animal shipments. We also employ best practices to minimize flight stress, so your pet arrives calm and comfortable.",
        "WHY_CHOOSE_PET_PAL_TITLE": "Why Choose Your Pet Pal?",
        "PET_PAL_FEATURE_1_TITLE": "Expert Animal Handling & In-Flight Care:",
        "PET_PAL_FEATURE_1_DESC": "Trained staff follow IATA Live Animals Regulations, managing loading, in-flight environment settings, and crew coordination for animal welfare.",
        "PET_PAL_FEATURE_2_TITLE": "DGCA Compliance:",
        "PET_PAL_FEATURE_2_DESC": "Complete health certificates, import/export permits, and quarantine clearances arranged through Animal Quarantine & Certification Services at major Indian airports.",
        "PET_PAL_FEATURE_3_TITLE": "IATA-Compliant Containers & Labeling:",
        "PET_PAL_FEATURE_3_DESC": "Secure, ventilated containers with proper cushioning, drainage, and “Live Animals” labeling in English and local language.",
        "PET_PAL_FEATURE_4_TITLE": "Personalized Care Plans:",
        "PET_PAL_FEATURE_4_DESC": "Customized feeding, exercise, and sedation protocols reduce stress, with 24-hour emergency contact details on the Air Waybill.",
        "PET_PAL_FEATURE_5_TITLE": "Global Service:",
        "PET_PAL_FEATURE_5_DESC": "Robust agents network provides secure pickup and delivery at home, airport, or veterinary facility, ensuring seamless continuity of care.",

        //EXPRESS_CARGO
        "EXPRESS_CARGO_TITLE": "Time Critical Express Cargo Transport",
        "EXPRESS_CARGO_DESC": "Express Cargo is our premium service for transporting time-critical shipments at optimal speed and efficiency along the supply chain under expert surveillance. From urgent documents and precious cargo to life-saving pharmaceuticals, blood samples for testing, aircraft spares, and AOG (Aircraft on Ground) components, we handle diverse express freight with qick serivce windows. Our multi-modal network combines air, road, and specialized transport to ensure your goods reach their destination within 24-72 hours for critical requirements.",
        "EXPRESS_CARGO_FEATURES_TITLE": "Delivery Options & Service Features",
        "EXPRESS_CARGO_FEATURE_1_TITLE": "Door-to-Door Express:",
        "EXPRESS_CARGO_FEATURE_1_DESC": "Complete pickup and delivery service from origin to final destination.",
        "EXPRESS_CARGO_FEATURE_2_TITLE": "Airport-to-Airport Express:",
        "EXPRESS_CARGO_FEATURE_2_DESC": "Fast terminal-to-terminal service for air cargo with reduced handling and expedited customs clearance.",

       //PERSONAL_EFFECTS
       "PERSONAL_EFFECTS_TITLE": "Personal Effects Transport",
       "PERSONAL_EFFECTS_DESC": "We specialize in transporting your personal effects safely and affordably. When airline baggage limits and excess fees threaten your move, Eastern Cargo Carriers provides seamless unaccompanied baggage solutions. Leveraging our global agents network, we manage packing, customs, and door-to-airport and door-to-door delivery of your household goods so you can focus on settling in, not shipping logistics.",
       "WHY_CHOOSE_PERSONAL_EFFECTS_TITLE": "Why Choose Our Personal Effects Transport?",
       "PERSONAL_EFFECTS_FEATURE_1_TITLE": "Excess Baggage Management:",
       "PERSONAL_EFFECTS_FEATURE_1_DESC": "Consolidate and ship items exceeding airline allowances as unaccompanied baggage, eliminating high fees.",
       "PERSONAL_EFFECTS_FEATURE_2_TITLE": "Door-to-Door Coverage:",
       "PERSONAL_EFFECTS_FEATURE_2_DESC": "Secure pickup from your home and delivery to any address worldwide via our extensive agents network.",
       "PERSONAL_EFFECTS_FEATURE_3_TITLE": "Professional Packing & Labelling:",
       "PERSONAL_EFFECTS_FEATURE_3_DESC": "Expert crating, cushioning, and labeling protect fragile goods in transit.",
       "PERSONAL_EFFECTS_FEATURE_4_TITLE": "Customs & Documentation Handling:",
       "PERSONAL_EFFECTS_FEATURE_4_DESC": "Complete paperwork and clearances to prevent delays and ensure regulatory compliance.",
       "PERSONAL_EFFECTS_FEATURE_5_TITLE": "End-to-End Support:",
       "PERSONAL_EFFECTS_FEATURE_5_DESC": "Live shipment updates and dedicated customer service from origin to final delivery.",

       //HEALTHCARE_LOGISTICS
       "HEALTHCARE_LOGISTICS_TITLE": "Healthcare Logistics",
       "HEALTHCARE_LOGISTICS_SUBTITLE": "Delivering health with precision and care since 1987",
       "HEALTHCARE_TRUST_TITLE": "Healthcare Logistics You Can Trust",
       "HEALTHCARE_TRUST_DESC": "When it comes to healthcare, every shipment is critical. At Eastern Cargo, we understand that lives can depend on the safe, fast, and precise delivery of your medical products. That’s why we provide specialized logistics solutions designed for the unique needs of the healthcare and life sciences industry.",
       "HEALTHCARE_FEATURE_1_TITLE": "Temperature-Controlled Transport:",
       "HEALTHCARE_FEATURE_1_DESC": "Validated packaging and cold chain solutions for frozen, chilled, and controlled room temperature shipments.",
       "HEALTHCARE_FEATURE_2_TITLE": "Time-Critical Deliveries:",
       "HEALTHCARE_FEATURE_2_DESC": "Priority handling for urgent shipments, with same-day and next-flight-out options.",
       "HEALTHCARE_FEATURE_3_TITLE": "Regulatory Compliance:",
       "HEALTHCARE_FEATURE_3_DESC": "Assistance with trade, customs, and industry regulations.",
       "HEALTHCARE_FEATURE_4_TITLE": "Sample & Equipment Handling:",
       "HEALTHCARE_FEATURE_4_DESC": "From diagnostic samples and clinical trial kits to surgical instruments and pharmaceuticals.",
       "WHY_CHOOSE_HEALTHCARE_TITLE": "Why Healthcare Leaders Choose Eastern Cargo:",
       "WHY_CHOOSE_HEALTHCARE_POINT_1": "✓ Dedicated healthcare logistics specialists.",
       "WHY_CHOOSE_HEALTHCARE_POINT_2": "✓ Nationwide and international reach with multimodal solutions.",
       "WHY_CHOOSE_HEALTHCARE_POINT_3": "✓ 24/7 operational support and contingency planning.",
       "WHY_CHOOSE_HEALTHCARE_POINT_4": "✓ Secure chain-of-custody protocols for sensitive shipments.",
       "HEALTHCARE_CLOSING_1": "When precision and reliability matter most — choose Eastern Cargo.",
       "HEALTHCARE_CLOSING_2": "Contact our healthcare logistics team today to discuss your needs.",
       "PASSION_TITLE": "A Passion for Time-Sensitive Shipments",
       "PASSION_DESC": "With a legacy in handling time-critical shipments since 1987, we bring unparalleled expertise to pharmaceutical logistics. Our team is known for successfully managing high-value life science products, including clinical trial shipments, new product launches, and deliveries to special and challenging territories.",
       "PASSION_FEATURE_1_TITLE": "Pharma-Focused Operations:",
       "PASSION_FEATURE_1_DESC": "A dedicated team trained specifically in the nuances of handling all types of life science products.",
       "PASSION_FEATURE_2_TITLE": "Quality & Compliance:",
       "PASSION_FEATURE_2_DESC": "A commitment to Quality Management, Operational Excellence, and superior customs capabilities ensures your shipments meet all regulatory standards.",
       "PASSION_FEATURE_3_TITLE": "Temperature-Controlled Solutions:",
       "PASSION_FEATURE_3_DESC": "We provide both Active and Passive pharma solutions to maintain strict temperature integrity for your cargo.",
       "PASSION_FEATURE_4_TITLE": "Established Carrier Relations:",
       "PASSION_FEATURE_4_DESC": "Over 30 years of strong partnerships with airlines and shipping companies, guaranteeing reliability, priority, and customer comfort.",
       "TEMP_SOLUTIONS_TITLE": "Our Temperature-Controlled Solutions",
       "ENVIROTAINERS_TITLE": "Envirotainers (Active)",
       "ENVIROTAINERS_DESC": "We provide state-of-the-art active container solutions, such as the Envirotainer RKN e1 and RAP e2, which use compressor-based cooling and electric heating to maintain precise product temperatures between +2°C to +8°C or +15°C to +25°C, regardless of ambient conditions.",
       "THERMAL_BLANKETS_TITLE": "Thermal Blankets (Passive)",
       "THERMAL_BLANKETS_DESC": "To prevent temperature spikes from direct sunlight or ambient conditions, we wrap all temperature-sensitive pallets in high-quality thermal blankets. This maintains the required temperature range during transportation, ensuring that drugs remain effective and safe to use.",
       "COOL_BOXES_TITLE": "Cool Boxes (Passive)",
       "COOL_BOXES_DESC": "For products requiring stricter temperature control, we utilize specialized cool boxes. These are an important component of pharmaceutical packaging, specifically designed to maintain the temperature of sensitive products like vaccines, insulin, and blood products during transportation and storage.",

       //DGR
       "DGR_TITLE": "Dangerous Goods Shipments",
       "DGR_SUBTITLE": "Dangerous Goods, Chemical & Hazardous Shipments – Expert Logistics Solutions",
       "DGR_DESC": "Transporting dangerous goods (DG), chemicals, and hazardous materials is a specialized domain, demanding utmost precision, expertise, and strict compliance with international safety standards. At Eastern Cargo we offer comprehensive DG logistics solutions for your shipments to move securely by air, sea, and road.",
       "DGR_SERVICES_TITLE": "Our DG, Chemical, and Hazardous Logistics Services",
       "DGR_FEATURE_1_TITLE": "Classification & Identification:",
       "DGR_FEATURE_1_DESC": "Accurate classification of chemicals and hazardous cargo as per IATA and local regulations. We assign correct UN numbers, hazard classes, and packing groups to every shipment.",
       "DGR_FEATURE_2_TITLE": "Certified Packaging & Labelling:",
       "DGR_FEATURE_2_DESC": "All items are packed, marked, and labelled with DG-compliant materials by trained personnel to prevent leaks, spills, and accidents. Compliance with international standards is our priority for every mode of transport.",
       "DGR_FEATURE_3_TITLE": "Regulatory Documentation & Compliance:",
       "DGR_FEATURE_3_DESC": "We manage full documentation—DG declarations, Safety Data Sheets (SDS/MSDS), permits, and insurance—ensuring flawless regulatory adherence with IATA.",
       "DGR_FEATURE_4_TITLE": "Trained Handling & Secure Transport:",
       "DGR_FEATURE_4_DESC": "Your hazardous cargo is managed by certified professionals using DG-approved containers.",
       "DGR_FEATURE_5_TITLE": "End-to-End DG Logistics Support:",
       "DGR_FEATURE_5_DESC": "Full-spectrum services from risk assessment and regulatory consultancy to shipment scheduling, delivery, and secure warehousing.",
       "DGR_CTA_1": "Ready to ship your dangerous goods, chemicals, or hazardous materials?",
       "DGR_CTA_2": "Contact our certified DG logistics team today for a personalized quote and expert guidance on global DG shipment compliance.",
       "DGR_QUOTE_TITLE": "Get Your Free Quote for Dangerous Goods Shipping",
       "DGR_QUOTE_SUBTITLE": "Contact our DG experts today for:",
       "DGR_QUOTE_POINT_1": "Free consultation on dangerous goods shipping requirements",
       "DGR_QUOTE_POINT_2": "DG exports from India documentation assistance.",
       "DGR_QUOTE_POINT_3": "Competitive pricing for hazardous cargo services India.",
       "DGR_QUOTE_POINT_4": "24/7 support for your dangerous goods logistics needs.",

       //PROJECT_LOGISTICS
       "PROJECT_LOGISTICS_TITLE": "Project Logistics",
       "PROJECT_LOGISTICS_SUBTITLE": "Specialized solutions for complex project cargo and heavy equipment transportation",
       "PROJECT_CARGO_SOLUTIONS_TITLE": "End-to-End Project Cargo Solutions",
       "PROJECT_CARGO_SOLUTIONS_DESC": "Our project logistics division specializes in handling complex, oversized, and heavy equipment shipments for industrial projects, power plants, oil & gas facilities, and infrastructure development. With decades of experience, we ensure seamless coordination from factory to final destination.",
       "OUR_PROJECT_LOGISTICS_SERVICES_TITLE": "Our Project Logistics Services",
       "PROJECT_SERVICE_1_TITLE": "Heavy Equipment Transport:",
       "PROJECT_SERVICE_1_DESC": "Specialized handling of machinery, turbines, generators, and industrial equipment with custom crating and secure transportation.",
       "PROJECT_SERVICE_2_TITLE": "Oversized Cargo Solutions:",
       "PROJECT_SERVICE_2_DESC": "Expert management of oversized shipments requiring special permits, route surveys, and specialized transport equipment.",
       "PROJECT_SERVICE_3_TITLE": "Project Coordination:",
       "PROJECT_SERVICE_3_DESC": "Comprehensive project management including documentation, customs clearance, insurance, and real-time tracking.",
       "PROJECT_SERVICE_4_TITLE": "Multi-Modal Transport:",
       "PROJECT_SERVICE_4_DESC": "Seamless integration of air, sea, and land transport modes for complex project requirements.",
       "PROJECT_SERVICE_5_TITLE": "Site Delivery & Installation:",
       "PROJECT_SERVICE_5_DESC": "On-site delivery coordination, equipment positioning, and installation support services.",
       "INDUSTRIES_WE_SERVE_TITLE": "Industries We Serve",
       "INDUSTRY_1_TITLE": "Oil & Gas",
       "INDUSTRY_1_DESC": "Pipeline equipment, drilling machinery, and refinery components",
       "INDUSTRY_2_TITLE": "Power Generation",
       "INDUSTRY_2_DESC": "Turbines, generators, transformers, and power plant equipment",
       "INDUSTRY_3_TITLE": "Manufacturing",
       "INDUSTRY_3_DESC": "Production lines, industrial machinery, and manufacturing equipment",
       "INDUSTRY_4_TITLE": "Infrastructure",
       "INDUSTRY_4_DESC": "Construction equipment, bridge components, and infrastructure materials.",

       //Human Remains
       'HUMAN_REMAINS_TITLE': 'Human Remains Transportation Services',
       'HUMAN_REMAINS_DESC': 'Eastern Cargo Carriers provides professional and compassionate human remains transportation services with the utmost dignity and respect. Our experienced team understands the sensitive nature of these services and ensures that every aspect of the transportation process is handled with care, professionalism, and complete confidentiality. We offer comprehensive solutions for both domestic and international human remains transportation, including all necessary documentation, customs clearance, and regulatory compliance.',
       'WHY_CHOOSE_HUMAN_REMAINS_TITLE': 'Why Choose Our Human Remains Transportation Services?',
       'HUMAN_REMAINS_FEATURE_1_TITLE': 'Compassionate Service:',
       'HUMAN_REMAINS_FEATURE_1_DESC': 'Our team provides sensitive, respectful handling with a complete understanding of the emotional nature of these services.',
       'HUMAN_REMAINS_FEATURE_2_TITLE': 'Complete Documentation:',
       'HUMAN_REMAINS_FEATURE_2_DESC': 'We handle all necessary paperwork including death certificates, embalming certificates, transit permits, and customs documentation.',
       'HUMAN_REMAINS_FEATURE_3_TITLE': 'International Expertise:',
       'HUMAN_REMAINS_FEATURE_3_DESC': 'Specialized knowledge of international regulations, airline requirements, and destination country protocols for human remains transportation.',
       'HUMAN_REMAINS_FEATURE_4_TITLE': '24/7 Support:',
       'HUMAN_REMAINS_FEATURE_4_DESC': 'Round-the-clock assistance and coordination to ensure timely and dignified transportation services.',
       'HUMAN_REMAINS_FEATURE_5_TITLE': 'Regulatory Compliance:',
       'HUMAN_REMAINS_FEATURE_5_DESC': 'Full compliance with IATA regulations, international health requirements, and destination country import/export regulations.',
       'SERVICES_INCLUDED_TITLE': 'Our Services Include:',
       'SERVICE_1_TITLE': 'International Repatriation:',
       'SERVICE_1_DESC': 'Complete international human remains transportation with all necessary documentation and customs clearance.',
       'SERVICE_2_TITLE': 'Domestic Transportation:',
       'SERVICE_2_DESC': 'Reliable domestic human remains transportation across India with proper handling and documentation.',
       'SERVICE_3_TITLE': 'Documentation Assistance:',
       'SERVICE_3_DESC': 'Complete assistance with all required documentation including death certificates, embalming certificates, and transit permits.',
       'SERVICE_4_TITLE': 'Customs Clearance:',
       'SERVICE_4_DESC': 'Expert customs clearance services for international human remains transportation with full regulatory compliance.',
       'SERVICE_5_TITLE': 'Airline Coordination:',
       'SERVICE_5_DESC': 'Direct coordination with airlines to ensure proper handling and timely transportation of human remains.'
    },

    es: {
        // Navigation
        'ABOUT US': 'ACERCA DE',
        'OUR SERVICES': 'NUESTROS SERVICIOS',
        'MORE': 'MÁS',
        'SPECIALIZED SERVICES': 'SERVICIOS ESPECIALIZADOS',
        'Healthcare Logistics': 'Logística de Salud',
        'DG Shipments': 'Envíos DG',
        'Project Logistics': 'Logística de Proyectos',
        'Our Team': 'Nuestro Equipo',
        'Calculator': 'Calculadora',
        'Customer Reviews': 'Opiniones de Clientes',
        'CONTACT US': 'CONTÁCTENOS',
        'Have any Questions?': '¿Tiene alguna pregunta?',
        'COMPANY_MAIN': 'EASTERN CARGO',
        'COMPANY_SUB': 'CARRIERS (I) PVT.LTD',
        'EMAIL_INFO': 'info@easterncargo.co.in',
        'EMAIL_LSETH': 'lseth@easterncargo.co.in',
        'PHONE_NO': '+91-22-67539999',
        'LANGUAGE_SELECTOR_TEXT': 'ES',
        
        // Hero Section
        'Worldwide Logistics': 'Logística Mundial',
        'International Air Freight': 'Flete Aéreo Internacional',
        'Contact Us': 'Contáctenos',
        'Get your free quote today': 'Obtenga su cotización gratuita hoy',
        'Reliable & Efficient': 'Confiable y Eficiente',
        'Multimodal Transport Network': 'Red de Transporte Multimodal',
        'Our Services': 'Nuestros Servicios',
        'Global Trade Solutions': 'Soluciones de Comercio Global',
        'Ocean Freight Solutions': 'Soluciones de Flete Marítimo',
        'Get a Quote': 'Obtener Cotización',
        'Select Service': 'Seleccionar Servicio',
        'Air Freight': 'Flete Aéreo',
        'Sea Freight': 'Flete Marítimo',
        'Land Transport': 'Transporte Terrestre',
        'Warehousing': 'Almacenamiento',
        'Pharma Logistics': 'Logística Farmacéutica',
        'DGR Shipments': 'Envíos DGR',
        'Project Logistics': 'Logística de Proyectos',
        'Name': 'Nombre',
        'Email': 'Correo Electrónico',
        'Phone': 'Teléfono',
        'Service Type': 'Tipo de Servicio',
        'Your Message': 'Su Mensaje',
        'Enter CAPTCHA': 'Introduzca CAPTCHA',
        'Request A Quote': 'Solicitar Cotización',
        'WRONG_CAPTCHA': '❌ CAPTCHA incorrecto',
        'CORRECT_CAPTCHA': '✅ CAPTCHA verificado',

        //WHY CHOOSE US
        'WHY CHOOSE US': 'POR QUÉ ELEGIRNOS',
        'Delivering Comprehensive Global Logistics Solutions': 'Entregando Soluciones Logísticas Globales Integrales.',
        'WHAT WE DO': 'QUÉ HACEMOS',
        'OUR AWARD': 'NUESTRO PREMIO',
        'COMPANY HISTORY': 'HISTORIA DE LA EMPRESA',
        'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Eastern Cargo es una empresa india independiente y de propiedad privada con más de 45 años de experiencia proporcionando servicios integrales de importación y exportación, cubriendo transporte aéreo, marítimo y terrestre, junto con despacho de aduanas experto. Entregamos soluciones en múltiples verticales como proyectos, productos químicos, farmacéuticos, prendas de vestir, bienes de ingeniería, carga líquida, carga peligrosa, logística con control de temperatura y comercio electrónico, todo respaldado por una fuerte presencia en toda la India.',
        'Warehouse Facility': 'Instalación de Almacén',
        'Air Freight Facility': 'Instalación de Flete Aéreo',
        'Cost Effective Pricing': 'Precios Rentables',
        'Timely Delivery': 'Entrega a Tiempo',
        'Container delivery': 'Entrega de Contenedores',
        'Best Team Member': 'Mejor Miembro del Equipo',
        'Learn More': 'Saber Más',
        'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Nuestra empresa se especializa en entregar soluciones de transporte aéreo y marítimo personalizadas para satisfacer las necesidades únicas de cada cliente. Ya sea flete internacional o carga sensible al tiempo, aseguramos servicios confiables, eficientes y rentables en cadenas de suministro globales. Entregamos soluciones en múltiples verticales como proyectos, productos químicos, farmacéuticos, prendas de vestir, bienes de ingeniería, carga líquida, carga peligrosa, logística con control de temperatura y comercio electrónico, todo respaldado por una fuerte presencia en toda la India.',
        'Global Network': 'Red Global',
        'Real-time Tracking': 'Seguimiento en Tiempo Real',
        'Customs Expertise': 'Experiencia en Aduanas',
        'Multi-modal Transport': 'Transporte Multimodal',
        'Risk Management': 'Gestión de Riesgos',
        'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.': 'Eastern Cargo ha recibido numerosos premios prestigiosos de la industria por la excelencia en flete y logística. Nuestro rendimiento consistente y dedicación a la calidad han ganado reconocimiento de aerolíneas líderes, transportistas globales y agentes logísticos de confianza, solidificando nuestra reputación como un socio confiable en soluciones de carga internacional.',
        'ISO Certified': 'Certificado ISO',
        'Industry Awards': 'Premios de la Industria',
        'Quality Standards': 'Estándares de Calidad',
        'Customer Recognition': 'Reconocimiento del Cliente',
        'AEO certified': 'Certificado AEO',
        'Excellence Certificates': 'Certificados de Excelencia',
        
        // Memberships
        'Memberships & Certifications': 'Membresías y Certificaciones',
        'Proud members of leading global logistics organizations': 'Orgullosos miembros de las principales organizaciones logísticas globales',
        'ISO 9001:2015': 'ISO 9001:2015',
        'AEO Certified': 'Certificado AEO',
        'WCA Member': 'Miembro WCA',
        'IATA Agent': 'Agente IATA',
        'FIATA Member': 'Miembro FIATA',
        'ACAAI Member': 'Miembro ACAAI',
        'MIFFA Member': 'Miembro MIFFA',
        
        // About Section
        'About EASTERN CARGO CARRIERS (I) PVT.LTD': 'Acerca de EASTERN CARGO CARRIERS (I) PVT.LTD',
        'Our Legacy & Commitment': 'Nuestro Legado y Compromiso',
        'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.': 'Como empresa india orgullosamente independiente y de propiedad privada, Eastern Cargo Carriers (I) Pvt. Ltd. aporta más de 45 años de experiencia dedicada al sector logístico. Nos especializamos en brindar un servicio integral a nuestros clientes, abarcando todos los aspectos de las importaciones y exportaciones en transporte aéreo, marítimo y terrestre, con un despacho de aduanas impecable.',
        'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.': 'Nuestra presencia global se ve reforzada por nuestro registro oficial como Operador de Transporte Multimodal (OMT) ante la Dirección General de Transporte Marítimo del Gobierno de la India. Esto nos permite ofrecer experiencia especializada en una amplia gama de sectores, incluyendo carga de proyecto, productos químicos, productos farmacéuticos, prendas de vestir, productos de ingeniería, carga líquida, carga peligrosa (Haz), envíos con temperatura controlada y logística de comercio electrónico.',
        'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.': 'Estamos comprometidos con los más altos estándares de calidad, como lo demuestran nuestra certificación ISO 9001, la certificación OEA para un despacho de aduanas optimizado y nuestro almacén que cumple con las normas GDP. Como miembros registrados de IATA y FIATA, nos adherimos a las mejores prácticas globales.',
        'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.': 'Con una sólida presencia en toda la India, ofrecemos soluciones flexibles y eficaces, desde el manejo de carga a temperatura controlada, peligrosa y líquida hasta la organización de chárteres aéreos y marítimos, ya sea parciales o totales. Nuestras capacidades de transporte marítimo abarcan desde contenedores FCL y LCL hasta carga fraccionada, RORO, cargas pesadas, equipos especiales y otras cargas especiales.',
        
        // Timeline
        'Ecc\'s Group Key Milestones in Aviation and Logistics': 'Hitos Clave del Grupo Ecc en Aviación y Logística',
        'YEAR_1979': '1979',
        'Custom House Agent': 'Agente de Aduanas',
        'Established as a CHA': 'Establecido como CHA',
        'CHA_TITLE': 'Agente de Aduanas (CHA)',
        'CHA_DESC': 'Eastern Cargo Carriers comenzó su andadura como Agente de Aduanas, proporcionando servicios esenciales de despacho de aduanas para operaciones de importación y exportación. Esto marcó la base de nuestra experiencia en logística.',
        'CHA_LIST_1': 'Servicios de despacho de aduanas',
        'CHA_LIST_2': 'Manejo de documentación',
        'CHA_LIST_3': 'Facilitación de importación/exportación',
        'YEAR_1984': '1984',
        'IATA Agent': 'Agente IATA',
        'Leveraging accreditation': 'Aprovechando la acreditación',
        'IATA_TITLE': 'Acreditación IATA',
        'IATA_DESC': 'Obtuvimos la acreditación de la Asociación de Transporte Aéreo Internacional (IATA), lo que nos permite ofrecer servicios completos de flete aéreo con alcance global y prácticas estándar de la industria.',
        'IATA_LIST_1': 'Red global de flete aéreo',
        'IATA_LIST_2': 'Cumplimiento de estándares IATA',
        'IATA_LIST_3': 'Operaciones de carga internacional',
        'YEAR_1989': '1989',
        'Charter Operation': 'Operación de Charter',
        'Initiated first charter': 'Iniciado primer charter',
        'CHARTER_TITLE': 'Lanzamiento de Operaciones de Charter',
        'CHARTER_DESC': 'Lanzamos nuestra división de operaciones de charter, proporcionando soluciones de aeronaves dedicadas para requisitos de carga urgentes y especializados. Esto expandió significativamente nuestra cartera de servicios.',
        'CHARTER_LIST_1': 'Charters de aeronaves dedicados',
        'CHARTER_LIST_2': 'Soluciones de carga urgente',
        'CHARTER_LIST_3': 'Servicios de transporte especializados',
        'YEAR_1994': '1994-99',
        'Network Expansion': 'Expansión de Red',
        'Achieved Pan-India presence': 'Lograda presencia en toda la India',
        'NETWORK_TITLE': 'Expansión de Red en toda la India',
        'NETWORK_DESC': 'Expandimos con éxito nuestras operaciones en toda la India, estableciendo una red integral de oficinas y centros de servicio para proporcionar soluciones logísticas a nivel nacional.',
        'NETWORK_LIST_1': 'Presencia a nivel nacional',
        'NETWORK_LIST_2': 'Múltiples ubicaciones de oficina',
        'NETWORK_LIST_3': 'Red de servicio integral',
        'YEAR_2005': '2005-11',
        'GSAs & Consolidation': 'GSAs y Consolidación',
        'Key GSA partnerships': 'Asociaciones clave de GSA',
        'GSA_TITLE': 'Asociaciones GSA y Consolidación',
        'GSA_DESC': 'Formamos asociaciones estratégicas de Agente General de Ventas (GSA) con las principales aerolíneas internacionales y líneas navieras, consolidando nuestra posición como un proveedor de logística líder.',
        'GSA_LIST_1': 'Asociaciones estratégicas con aerolíneas',
        'GSA_LIST_2': 'Alianzas de envío global',
        'GSA_LIST_3': 'Capacidades de servicio mejoradas',
        'YEAR_2015': '2015-16',
        'Pharma Expertise': 'Experiencia Farmacéutica',
        'Specialized services': 'Servicios especializados',
        'PHARMA_TITLE': 'Experiencia en Logística Farmacéutica',
        'PHARMA_DESC': 'Desarrollamos experiencia especializada en logística farmacéutica, incluyendo transporte con control de temperatura y almacenamiento compatible con GDP para productos de ciencias de la vida.',
        'PHARMA_LIST_1': 'Soluciones con control de temperatura',
        'PHARMA_LIST_2': 'Almacenamiento compatible con GDP',
        'PHARMA_LIST_3': 'Experiencia específica en farmacéutica',
        'YEAR_2017': '2017-18',
        'Temp Warehouse': 'Almacén Temporal',
        'Pharma packaging': 'Embalaje farmacéutico',
        'TEMP_WAREHOUSE_TITLE': 'Almacén con Control de Temperatura',
        'TEMP_WAREHOUSE_DESC': 'Establecimos instalaciones de almacenamiento dedicadas con control de temperatura para productos farmacéuticos, asegurando un almacenamiento y manejo adecuados de carga sensible.',
        'TEMP_WAREHOUSE_LIST_1': 'Almacenamiento con control de temperatura',
        'TEMP_WAREHOUSE_LIST_2': 'Servicios de embalaje farmacéutico',
        'TEMP_WAREHOUSE_LIST_3': 'Protocolos de garantía de calidad',
        'YEAR_2019': '2019-20',
        'Critical Response': 'Respuesta Crítica',
        'Imported life-saving drugs': 'Medicamentos que salvan vidas importados',
        'CRITICAL_RESPONSE_TITLE': 'Operaciones de Respuesta Crítica',
        'CRITICAL_RESPONSE_DESC': 'Manejamos con éxito operaciones de respuesta crítica durante la pandemia, importando medicamentos que salvan vidas y suministros médicos con una velocidad y eficiencia sin precedentes.',
        'CRITICAL_RESPONSE_LIST_1': 'Suministros médicos de emergencia',
        'CRITICAL_RESPONSE_LIST_2': 'Logística de respuesta rápida',
        'CRITICAL_RESPONSE_LIST_3': 'Transporte de medicamentos que salvan vidas',
        'YEAR_2020': '2020-21',
        'Governor\'s Award': 'Premio del Gobernador',
        'For Pharma Exports': 'Para Exportaciones Farmacéuticas',
        'GOVERNOR_AWARD_TITLE': 'Reconocimiento del Premio del Gobernador',
        'GOVERNOR_AWARD_DESC': 'Recibimos el prestigioso Premio del Gobernador por la excelencia en las exportaciones farmacéuticas, reconociendo nuestra destacada contribución al sector de la logística de la salud.',
        'GOVERNOR_AWARD_LIST_1': 'Excelencia en exportaciones farmacéuticas',
        'GOVERNOR_AWARD_LIST_2': 'Reconocimiento de la industria',
        'GOVERNOR_AWARD_LIST_3': 'Liderazgo en logística de la salud',
        
        // Services
        'Wide variety of logistics services': 'Amplia variedad de servicios logísticos',
        'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.': 'Nuestra empresa de logística ofrece una amplia gama de servicios adaptados para satisfacer las necesidades únicas de cada cliente. Desde almacenamiento y distribución hasta gestión de transporte y suministro.',
        'Air Freight (Export & Import)': 'Flete Aéreo (Exportación e Importación)',
        'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.': 'Con más de 40 años en el mercado, tenemos un fuerte alcance con una amplia gama de transportistas aéreos para ofrecer precios agresivos y soluciones a medida.',
        'Ocean Freight (Import & Export)': 'Flete Marítimo (Importación y Exportación)',
        'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.': 'Servicios integrales de flete marítimo para todas sus necesidades de importación y exportación, asegurando una entrega confiable y oportuna en todo el mundo.',
        'Customs Brokerage': 'Agente de Aduanas',
        'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.': 'Ofrecemos una gama de servicios aduaneros con valor agregado para mover sus envíos a través de aduanas de manera rápida y eficiente.',
        'Warehouse & Distribution': 'Almacenamiento y Distribución',
        'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.': 'Para asegurar que su cadena de suministro funcione sin problemas, ofrecemos servicios dedicados y compartidos de almacenamiento y distribución.',
        'Air Charter': 'Charter Aéreo',
        'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.': 'Desde 1989, hemos proporcionado servicios urgentes e integrales de Charter de Carga Aérea, manejando solicitudes con entrenamiento exhaustivo.',
        'Your Pet Pal': 'Su Compañero Mascota',
        'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.': 'Desde gatos y perros hasta caballos, tenemos el conocimiento para manejar y transportar sus mascotas con gentileza y cuidado a su destino.',
        'Express Logistics': 'Logística Express',
        'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.': 'Nuestros servicios de carga express internacional garantizan una entrega rápida y confiable para sus envíos globales urgentes.',
        'Unaccompanied Baggage Shipping': 'Envío de Equipaje No Acompañado',
        'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.': 'El envío de equipaje personal elimina el estrés de su mudanza al manejar los artículos en exceso con cuidado experto. Gestionamos embalaje profesional, despacho de aduanas.',
        
        // Customer Reviews
        'What our clients say': 'Lo que dicen nuestros clientes',
        'Trusted experiences shared by our customers': 'Experiencias de confianza compartidas por nuestros clientes.',
        'TESTIMONIAL_1_TITLE': 'Entrega Súper Rápida',
        'TESTIMONIAL_1_DESC': 'Eastern Cargo Carriers proporcionó un excelente servicio para mi envío. Desde la recogida hasta la entrega, todo fue perfecto y a tiempo. Realmente aprecio su profesionalismo y su soporte al cliente.',
        'TESTIMONIAL_2_TITLE': 'Servicios Excelentes',
        'TESTIMONIAL_2_DESC': 'Compañía muy profesional con servicios confiables y sin demoras. Cada envío es manejado sin problemas y a tiempo, dándome total tranquilidad. Verdaderamente una de las mejores opciones para soluciones de carga confiables.',
        'TESTIMONIAL_3_TITLE': 'Socio Confiable',
        'TESTIMONIAL_3_DESC': 'Eastern Cargo Carriers se ha convertido en nuestro socio de confianza. Su puntualidad, profesionalismo y confiabilidad aseguran que cada entrega sea manejada con cuidado y siempre a tiempo.',
        'TESTIMONIAL_4_TITLE': 'Asequible y Seguro',
        'TESTIMONIAL_4_DESC': 'Eastern Cargo Carriers ofrece la forma más económica y segura de enviar cargas desde los EAU. Su puntualidad, profesionalismo y confiabilidad hacen que todo el proceso sea suave y libre de estrés.',
        'TESTIMONIAL_5_TITLE': 'Soporte Excepcional',
        'TESTIMONIAL_5_DESC': 'Eastern Cargo Carriers me impresionó con su equipo de soporte profesional. Proporcionaron actualizaciones oportunas, manejaron cada consulta con cuidado y se aseguraron de que mi envío llegara puntualmente y sin problemas.',
        'TESTIMONIAL_6_TITLE': 'Confiable por Años',
        'TESTIMONIAL_6_DESC': 'Hemos confiado en Eastern Cargo Carriers durante años, y su consistencia en puntualidad, profesionalismo y servicio confiable los ha convertido en nuestra primera opción para cada envío.',
        
        // Calculator
        'Smart Cargo Calculator': 'Calculadora Inteligente de Carga',
        'Centimeters (CM)': 'Centímetros (CM)',
        'Inches (IN)': 'Pulgadas (IN)',
        'Package Dimensions': 'Dimensiones del Paquete',
        '+ Add Package': '+ Agregar Paquete',
        'Reset': 'Reiniciar',
        'Calculate': 'Calcular',
        
        // Career/Contact Forms
        'Join Our Team': 'Únete a Nuestro Equipo',
        'Build your career with Eastern Cargo Carriers – explore exciting opportunities today.': 'Construye tu carrera con Eastern Cargo Carriers – explora emocionantes oportunidades hoy.',
        'Upload Resume': 'Subir Currículum',
        'Your Message (Optional)': 'Su Mensaje (Opcional)',
        'Submit Application': 'Enviar Solicitud',
        'Request your free logistics quote today and experience hassle-free shipping.': 'Solicita hoy tu cotización de logística gratuita y experimenta un envío sin complicaciones.',

        // Footer
        'FOOTER_HEADING': 'Eastern Cargo Carriers (I) Pvt.Ltd.',
        'FOOTER_ADDRESS': 'Unidad #25/26/27, Adarsh Industrial Estate, Sahar Road, Chakala, Andheri (East), Mumbai – 400 099',
        'Quick Links': 'Enlaces Rápidos',
        'About Us': 'Acerca de Nosotros',
        'Careers': 'Carreras',
        'Get a Quote': 'Obtener una Cotización',
        'Our Team': 'Nuestro Equipo',
        'Our Services': 'Nuestros Servicios',
        'Client Reviews': 'Opiniones de Clientes',
        'Specialized Services': 'Servicios Especializados',
        'Express Logistics': 'Logística Express',
        'Healthcare Logistics': 'Logística de Salud',
        'DG Shipments': 'Envíos DG',
        'Project Logistics': 'Logística de Proyectos',
        'Find Us': 'Encuéntrenos',
        'Follow us :': 'Síguenos :',
        'COPYRIGHT': '© Copyright 2025. Todos los Derechos Reservados por Eastern Cargo Carriers (I) Pvt.Ltd',
        'Select Language': 'Seleccionar Idioma',
        'CLOSE_MODAL': '×',
        'English': 'Inglés',
        'Spanish': 'Español',
        'French': 'Francés',
        'German': 'Alemán',
        'Chinese': 'Chino',
        'Japanese': 'Japonés',

        //Menu
        'ABOUT US': 'ACERCA DE',
        'OUR SERVICES': 'NUESTROS SERVICIOS',
        'MORE': 'MÁS',
        'SPECIALIZED SERVICES': 'SERVICIOS ESPECIALIZADOS',
        'Healthcare Logistics': 'Logística de Salud',
        'DG Shipments': 'Envíos DG',
        'Project Logistics': 'Logística de Proyectos',
        'Our Team': 'Nuestro Equipo',
        'Calculator': 'Calculadora',
        'Customer Reviews': 'Opiniones de Clientes',
        'CONTACT US': 'CONTÁCTENOS',
        'Have any Questions?': '¿Tiene alguna pregunta?',

        //Air Freight
        "Air Freight (Export & Import Services)": "Flete Aéreo (Servicios de Exportación e Importación)",
        "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.": "Con más de 40 años de liderazgo en el mercado indio, Eastern Cargo Carriers (I) Pvt. Ltd. se destaca por su amplio alcance y sólidas alianzas con aerolíneas tanto regionales como internacionales. Además, empoderamos a nuestros clientes con una robusta red de agentes globales, permitiendo verdaderas soluciones de flete aéreo de puerta a puerta, desde la recogida en origen hasta la entrega final en destino. Esta combinación inigualable nos permite ofrecer un servicio confiablemente rápido, tarifas altamente competitivas y un control total a los principales destinos de todo el mundo. Ya sea que necesite envíos aéreos estándar o logística de carga especializada y sensible, nuestras soluciones a medida aseguran que su carga se mueva con rapidez, seguridad y eficiencia en cada paso del camino.",
        "Why Choose Our Air Freight Services?": "¿Por Qué Elegir Nuestros Servicios de Flete Aéreo?",
        "Aggressive, Competitive Rates:": "Tarifas Agresivas y Competitivas:",
        "Leverage our airline relationships for the best pricing to key global hubs.": "Aproveche nuestras relaciones con las aerolíneas para obtener los mejores precios a los principales centros globales.",
        "Faster Transit Times:": "Tiempos de Tránsito Más Rápidos:",
        "Priority access ensures your cargo arrives on schedule—every time.": "El acceso prioritario garantiza que su carga llegue a tiempo, siempre.",
        "Advanced Cold Chain & Temperature Control:": "Cadena de Frío y Control de Temperatura Avanzados:",
        "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.": "Manejamos con experiencia envíos en contenedores refrigerados, sensibles a la temperatura y activos (Envirotainer).",
        "Specialized Cargo Handling:": "Manejo de Carga Especializada:",
        "From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.": "Desde DGR (mercancías peligrosas) hasta objetos de valor, mascotas/animales vivos y restos humanos, nuestro equipo lo maneja todo con cuidado y cumplimiento.",
        "End-to-End Service:": "Servicio Integral:",
        "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.": "Reciba soluciones completas que incluyen recogida/entrega, embalaje, etiquetado, documentación, seguro y despacho de aduanas.",
        "Additional Capabilities": "Capacidades Adicionales",
        "Cargo consolidation for cost efficiency to key destinations.": "Consolidación de carga para una mayor rentabilidad a destinos clave.",
        "Expert handling of personal effects, household goods, and chartered flight operations.": "Manejo experto de efectos personales, enseres domésticos y operaciones de vuelos chárter.",
        "Full spectrum of value-added services with and expert support at every step.": "Un espectro completo de servicios de valor añadido con soporte experto en cada paso.",
        
        //OCEAN_FREIGHT
        "OCEAN_FREIGHT_TITLE": "Flete Marítimo (Servicios de Importación y Exportación)",
        "WHY_CHOOSE_OCEAN_FREIGHT_TITLE": "¿Por Qué Elegir Nuestros Servicios de Flete Marítimo?",
        "OCEAN_FREIGHT_FEATURE_1_TITLE": "Soluciones Integrales FCL y LCL:",
        "OCEAN_FREIGHT_FEATURE_1_DESC": "Opciones de reserva flexibles con tarifas competitivas a través de nuestras alianzas establecidas con líneas navieras para contenedores completos y consolidados.",
        "OCEAN_FREIGHT_FEATURE_2_TITLE": "Experiencia en Carga Especializada:",
        "OCEAN_FREIGHT_FEATURE_2_DESC": "Manejo experto de ODC (carga de dimensiones especiales), carga de proyectos, materiales peligrosos y carga refrigerada con soluciones de temperatura controlada.",
        "OCEAN_FREIGHT_FEATURE_3_TITLE": "Integración de Servicios de Extremo a Extremo:",
        "OCEAN_FREIGHT_FEATURE_3_DESC": "Gestión logística completa que incluye despacho de aduanas, embalaje, paletización, seguro marítimo y manejo DDU/DDP.",
        "OCEAN_FREIGHT_FEATURE_4_TITLE": "Red Global y Especialización en Rutas Comerciales:",
        "OCEAN_FREIGHT_FEATURE_4_DESC": "Una extensa red de agentes en el extranjero garantiza un servicio confiable en rutas comerciales especializadas con experiencia local.",
        "OCEAN_FREIGHT_FEATURE_5_TITLE": "Servicios Marítimos de Valor Añadido:",
        "OCEAN_FREIGHT_FEATURE_5_DESC": "Soporte integral que incluye consolidación/desconsolidación, almacenamiento, distribución, transporte y manejo de efectos personales para una gestión completa de la cadena de suministro.",

        //CUSTOMS_BROKERAGE
        "CUSTOMS_BROKERAGE_TITLE": "Servicios de Agente de Aduanas",
        "CUSTOMS_BROKERAGE_DESC": "Navegar por las complejas regulaciones del comercio internacional requiere servicios expertos de agente de aduanas que garanticen un despacho rápido y conforme para sus envíos de exportación. Como agentes de aduanas certificados por OEA con una profunda experiencia regulatoria, agilizamos todo el proceso aduanero, minimizamos los retrasos y optimizamos los costos de los aranceles para empresas de todas las industrias.",
        "WHY_CHOOSE_CUSTOMS_BROKERAGE_TITLE": "¿Por Qué Elegir Nuestros Servicios de Agente de Aduanas?",
        "CUSTOMS_BROKERAGE_FEATURE_1_TITLE": "Experiencia Certificada por OEA:",
        "CUSTOMS_BROKERAGE_FEATURE_1_DESC": "El estatus de Operador Económico Autorizado garantiza un procesamiento aduanero más rápido y confiable con inspecciones reducidas.",
        "CUSTOMS_BROKERAGE_FEATURE_2_TITLE": "Cumplimiento Regulatorio Completo:",
        "CUSTOMS_BROKERAGE_FEATURE_2_DESC": "Gestión completa de la documentación, clasificación arancelaria y cumplimiento de todas las regulaciones de importación/exportación.",
        "CUSTOMS_BROKERAGE_FEATURE_3_TITLE": "Optimización de Aranceles y Costos:",
        "CUSTOMS_BROKERAGE_FEATURE_3_DESC": "Clasificación arancelaria estratégica y utilización de acuerdos comerciales para minimizar los aranceles y tasas aduaneras.",
        "CUSTOMS_BROKERAGE_FEATURE_4_TITLE": "Manejo de Carga Especializada:",
        "CUSTOMS_BROKERAGE_FEATURE_4_DESC": "Despacho experto de materiales peligrosos, mercancías restringidas y envíos de alto valor con cumplimiento normativo.",
        "CUSTOMS_BROKERAGE_FEATURE_5_TITLE": "Soporte de Extremo a Extremo:",
        "CUSTOMS_BROKERAGE_FEATURE_5_DESC": "Servicio integral desde la preparación de la documentación hasta la entrega final.",

        //WAREHOUSE
        "WAREHOUSE_TITLE": "Servicios de Almacenamiento y Distribución",
        "WAREHOUSE_DESC": "En Eastern Cargo Carriers (I) Pvt.LTD, nos aseguramos de que su cadena de suministro funcione sin interrupciones, ofreciendo servicios de almacenamiento y distribución tanto dedicados como compartidos, adaptados a sus necesidades. Nuestro experimentado equipo de asociados brinda un sólido apoyo en cada etapa del transporte, gestionando eficientemente sus mercancías desde el almacenamiento hasta la entrega final. Ya sea que necesite almacenamiento a corto o largo plazo, ofrecemos instalaciones seguras y organizadas, equipadas para paletización, embalaje, retractilado y etiquetado. Nuestra red estratégica de almacenamiento permite un acceso rápido y confiable a las principales rutas comerciales, asegurando que sus productos lleguen a los clientes a tiempo, siempre. También manejamos requisitos especializados como la fumigación para mantener los estándares de seguridad de los productos y cumplir con las regulaciones internacionales.",

        //AIR_CHARTER
        "AIR_CHARTER_TITLE": "Servicios de Vuelos Chárter Aéreos",
        "AIR_CHARTER_DESC": "Desde 1989, Eastern Cargo Carriers se ha especializado en el flete aéreo urgente y completo para envíos críticos en tiempo y especializados. Nuestro dedicado equipo está expertamente capacitado para manejar cargas complejas, desde productos farmacéuticos que salvan vidas durante la pandemia hasta equipos industriales de gran tamaño, asegurando que su carga sea entregada con una velocidad, seguridad y flexibilidad inigualables. Ofrecemos opciones de chárter completo y parcial, proporcionando un control total sobre el proceso de transporte, con una gestión integral que incluye el posicionamiento de la aeronave, el manejo, la coordinación aduanera y la entrega de aeropuerto a aeropuerto en los principales aeropuertos de la India.",
        "WHY_CHOOSE_AIR_CHARTER_TITLE": "¿Por Qué Elegir Nuestros Servicios de Vuelos Chárter Aéreos?",
        "AIR_CHARTER_FEATURE_1_TITLE": "Opciones de Chárter Personalizadas:",
        "AIR_CHARTER_FEATURE_1_DESC": "Vuelos chárter completos o parciales, de ida o de ida y vuelta, adaptados a su horario y requisitos de carga.",
        "AIR_CHARTER_FEATURE_2_TITLE": "Experiencia en Logística de Emergencia:",
        "AIR_CHARTER_FEATURE_2_DESC": "Historial probado en la ejecución de misiones críticas, como la exportación e importación de productos farmacéuticos durante la pandemia, bajo plazos estrictos.",
        "AIR_CHARTER_FEATURE_3_TITLE": "Manejo Integral:",
        "AIR_CHARTER_FEATURE_3_DESC": "Gestión completa del chárter, desde el posicionamiento de la aeronave hasta la carga especializada, el despacho de aduanas y la entrega, en cumplimiento de las directrices de la DGCA.",
        "AIR_CHARTER_FEATURE_4_TITLE": "Acceso Estratégico a Aeropuertos:",
        "AIR_CHARTER_FEATURE_4_DESC": "Operaciones en los principales aeropuertos aduaneros de la India, asegurando una rápida rotación y un alcance máximo.",

        //PET_PAL
        "PET_PAL_TITLE": "Tu Amigo Mascota: Transporte de Animales Vivos",
        "PET_PAL_DESC": "Ya sea su amado gato o perro, o incluso caballos y elefantes, Eastern Cargo Carriers se asegura de que cada mascota viaje con el máximo cuidado. Nuestras instalaciones especializadas, vehículos con clima controlado y equipo capacitado en el manejo de animales agilizan los envíos de animales vivos tanto de entrada como de salida. También empleamos las mejores prácticas para minimizar el estrés del vuelo, para que su mascota llegue tranquila y cómoda.",
        "WHY_CHOOSE_PET_PAL_TITLE": "¿Por Qué Elegir Tu Amigo Mascota?",
        "PET_PAL_FEATURE_1_TITLE": "Manejo Experto de Animales y Cuidado en Vuelo:",
        "PET_PAL_FEATURE_1_DESC": "Personal capacitado sigue las Regulaciones de Animales Vivos de la IATA, gestionando la carga, la configuración del ambiente en vuelo y la coordinación con la tripulación para el bienestar animal.",
        "PET_PAL_FEATURE_2_TITLE": "Cumplimiento de la DGCA:",
        "PET_PAL_FEATURE_2_DESC": "Certificados de salud completos, permisos de importación/exportación y autorizaciones de cuarentena gestionados a través de los Servicios de Cuarentena y Certificación Animal en los principales aeropuertos de la India.",
        "PET_PAL_FEATURE_3_TITLE": "Contenedores y Etiquetado Conformes a la IATA:",
        "PET_PAL_FEATURE_3_DESC": "Contenedores seguros y ventilados con amortiguación adecuada, drenaje y etiquetado de “Animales Vivos” en inglés y en el idioma local.",
        "PET_PAL_FEATURE_4_TITLE": "Planes de Cuidado Personalizados:",
        "PET_PAL_FEATURE_4_DESC": "Protocolos personalizados de alimentación, ejercicio y sedación para reducir el estrés, con detalles de contacto de emergencia 24 horas en la Guía Aérea.",
        "PET_PAL_FEATURE_5_TITLE": "Servicio Global:",
        "PET_PAL_FEATURE_5_DESC": "Una sólida red de agentes proporciona una recogida y entrega seguras en el hogar, el aeropuerto o un centro veterinario, asegurando una continuidad del cuidado sin interrupciones.",

        //EXPRESS_CARGO
        "EXPRESS_CARGO_TITLE": "Transporte de Carga Urgente y Crítica",
        "EXPRESS_CARGO_DESC": "Express Cargo es nuestro servicio premium para transportar envíos de tiempo crítico con velocidad y eficiencia óptimas a lo largo de la cadena de suministro bajo supervisión experta. Desde documentos urgentes y carga valiosa hasta productos farmacéuticos que salvan vidas, muestras de sangre para pruebas, repuestos de aeronaves y componentes AOG (Aeronave en Tierra), manejamos una diversa gama de fletes expresos con ventanas de servicio rápidas. Nuestra red multimodal combina transporte aéreo, terrestre y especializado para asegurar que sus mercancías lleguen a su destino en 24-72 horas para requerimientos críticos.",
        "EXPRESS_CARGO_FEATURES_TITLE": "Opciones de Entrega y Características del Servicio",
        "EXPRESS_CARGO_FEATURE_1_TITLE": "Express Puerta a Puerta:",
        "EXPRESS_CARGO_FEATURE_1_DESC": "Servicio completo de recogida y entrega desde el origen hasta el destino final.",
        "EXPRESS_CARGO_FEATURE_2_TITLE": "Express de Aeropuerto a Aeropuerto:",
        "EXPRESS_CARGO_FEATURE_2_DESC": "Servicio rápido de terminal a terminal para carga aérea con manejo reducido y despacho de aduanas acelerado.",

        //PERSONAL_EFFECTS
        "PERSONAL_EFFECTS_TITLE": "Transporte de Efectos Personales",
        "PERSONAL_EFFECTS_DESC": "Nos especializamos en transportar sus efectos personales de forma segura y asequible. Cuando los límites de equipaje de las aerolíneas y las tarifas por exceso amenazan su mudanza, Eastern Cargo Carriers ofrece soluciones integrales para equipaje no acompañado. Aprovechando nuestra red de agentes globales, gestionamos el embalaje, la aduana y la entrega de puerta a aeropuerto y de puerta a puerta de sus enseres domésticos para que pueda concentrarse en instalarse, no en la logística del envío.",
        "WHY_CHOOSE_PERSONAL_EFFECTS_TITLE": "¿Por Qué Elegir Nuestro Transporte de Efectos Personales?",
        "PERSONAL_EFFECTS_FEATURE_1_TITLE": "Gestión de Exceso de Equipaje:",
        "PERSONAL_EFFECTS_FEATURE_1_DESC": "Consolide y envíe los artículos que excedan las franquicias de las aerolíneas como equipaje no acompañado, eliminando las altas tarifas.",
        "PERSONAL_EFFECTS_FEATURE_2_TITLE": "Cobertura de Puerta a Puerta:",
        "PERSONAL_EFFECTS_FEATURE_2_DESC": "Recogida segura en su hogar y entrega en cualquier dirección del mundo a través de nuestra extensa red de agentes.",
        "PERSONAL_EFFECTS_FEATURE_3_TITLE": "Embalaje y Etiquetado Profesional:",
        "PERSONAL_EFFECTS_FEATURE_3_DESC": "Embalaje experto, amortiguación y etiquetado para proteger los bienes frágiles durante el tránsito.",
        "PERSONAL_EFFECTS_FEATURE_4_TITLE": "Manejo de Aduanas y Documentación:",
        "PERSONAL_EFFECTS_FEATURE_4_DESC": "Documentación y despachos completos para prevenir retrasos y asegurar el cumplimiento normativo.",
        "PERSONAL_EFFECTS_FEATURE_5_TITLE": "Soporte de Extremo a Extremo:",
        "PERSONAL_EFFECTS_FEATURE_5_DESC": "Actualizaciones del envío en tiempo real y servicio al cliente dedicado desde el origen hasta la entrega final.",

        //HEALTHCARE_LOGISTICS
        "HEALTHCARE_LOGISTICS_TITLE": "Logística Sanitaria",
        "HEALTHCARE_LOGISTICS_SUBTITLE": "Entregando salud con precisión y cuidado desde 1987",
        "HEALTHCARE_TRUST_TITLE": "Logística Sanitaria en la que Puede Confiar",
        "HEALTHCARE_TRUST_DESC": "Cuando se trata de atención médica, cada envío es crítico. En Eastern Cargo, entendemos que las vidas pueden depender de la entrega segura, rápida y precisa de sus productos médicos. Por eso ofrecemos soluciones logísticas especializadas diseñadas para las necesidades únicas de la industria de la salud y las ciencias de la vida.",
        "HEALTHCARE_FEATURE_1_TITLE": "Transporte con Temperatura Controlada:",
        "HEALTHCARE_FEATURE_1_DESC": "Embalajes validados y soluciones de cadena de frío para envíos congelados, refrigerados y a temperatura ambiente controlada.",
        "HEALTHCARE_FEATURE_2_TITLE": "Entregas de Tiempo Crítico:",
        "HEALTHCARE_FEATURE_2_DESC": "Manejo prioritario para envíos urgentes, con opciones de entrega el mismo día y en el próximo vuelo disponible.",
        "HEALTHCARE_FEATURE_3_TITLE": "Cumplimiento Regulatorio:",
        "HEALTHCARE_FEATURE_3_DESC": "Asistencia con las regulaciones comerciales, aduaneras y de la industria.",
        "HEALTHCARE_FEATURE_4_TITLE": "Manejo de Muestras y Equipos:",
        "HEALTHCARE_FEATURE_4_DESC": "Desde muestras de diagnóstico y kits de ensayos clínicos hasta instrumentos quirúrgicos y productos farmacéuticos.",
        "WHY_CHOOSE_HEALTHCARE_TITLE": "Por Qué los Líderes del Sector Sanitario Eligen a Eastern Cargo:",
        "WHY_CHOOSE_HEALTHCARE_POINT_1": "✓ Especialistas dedicados en logística sanitaria.",
        "WHY_CHOOSE_HEALTHCARE_POINT_2": "✓ Alcance nacional e internacional con soluciones multimodales.",
        "WHY_CHOOSE_HEALTHCARE_POINT_3": "✓ Soporte operativo 24/7 y planificación de contingencias.",
        "WHY_CHOOSE_HEALTHCARE_POINT_4": "✓ Protocolos seguros de cadena de custodia para envíos sensibles.",
        "HEALTHCARE_CLOSING_1": "Cuando la precisión y la fiabilidad son lo más importante, elija Eastern Cargo.",
        "HEALTHCARE_CLOSING_2": "Contacte a nuestro equipo de logística sanitaria hoy mismo para discutir sus necesidades.",
        "PASSION_TITLE": "Pasión por los Envíos de Tiempo Crítico",
        "PASSION_DESC": "Con un legado en el manejo de envíos de tiempo crítico desde 1987, aportamos una experiencia inigualable a la logística farmacéutica. Nuestro equipo es conocido por gestionar con éxito productos de ciencias de la vida de alto valor, incluyendo envíos de ensayos clínicos, lanzamientos de nuevos productos y entregas a territorios especiales y desafiantes.",
        "PASSION_FEATURE_1_TITLE": "Operaciones Enfocadas en Farmacia:",
        "PASSION_FEATURE_1_DESC": "Un equipo dedicado y entrenado específicamente en los matices del manejo de todo tipo de productos de ciencias de la vida.",
        "PASSION_FEATURE_2_TITLE": "Calidad y Cumplimiento:",
        "PASSION_FEATURE_2_DESC": "Un compromiso con la Gestión de Calidad, la Excelencia Operacional y capacidades aduaneras superiores asegura que sus envíos cumplan con todas las normativas regulatorias.",
        "PASSION_FEATURE_3_TITLE": "Soluciones de Temperatura Controlada:",
        "PASSION_FEATURE_3_DESC": "Ofrecemos soluciones farmacéuticas tanto Activas como Pasivas para mantener una estricta integridad de la temperatura de su carga.",
        "PASSION_FEATURE_4_TITLE": "Relaciones Establecidas con Transportistas:",
        "PASSION_FEATURE_4_DESC": "Más de 30 años de sólidas alianzas con aerolíneas y compañías navieras, garantizando fiabilidad, prioridad y comodidad para el cliente.",
        "TEMP_SOLUTIONS_TITLE": "Nuestras Soluciones de Temperatura Controlada",
        "ENVIROTAINERS_TITLE": "Envirotainers (Activos)",
        "ENVIROTAINERS_DESC": "Ofrecemos soluciones de contenedores activos de última generación, como el Envirotainer RKN e1 y RAP e2, que utilizan refrigeración por compresor y calefacción eléctrica para mantener temperaturas precisas del producto entre +2°C y +8°C o +15°C y +25°C, independientemente de las condiciones ambientales.",
        "THERMAL_BLANKETS_TITLE": "Mantas Térmicas (Pasivas)",
        "THERMAL_BLANKETS_DESC": "Para evitar picos de temperatura por la luz solar directa o las condiciones ambientales, envolvemos todos los palés sensibles a la temperatura en mantas térmicas de alta calidad. Esto mantiene el rango de temperatura requerido durante el transporte, asegurando que los medicamentos sigan siendo efectivos y seguros para su uso.",
        "COOL_BOXES_TITLE": "Cajas Refrigeradas (Pasivas)",
        "COOL_BOXES_DESC": "Para productos que requieren un control de temperatura más estricto, utilizamos cajas refrigeradas especializadas. Estas son un componente importante del embalaje farmacéutico, diseñadas específicamente para mantener la temperatura de productos sensibles como vacunas, insulina y productos sanguíneos durante el transporte y almacenamiento.",

        //DGR
        "DGR_TITLE": "Envíos de Mercancías Peligrosas",
        "DGR_SUBTITLE": "Mercancías Peligrosas, Químicas y Envíos Peligrosos – Soluciones Logísticas Expertas",
        "DGR_DESC": "El transporte de mercancías peligrosas (DG), productos químicos y materiales peligrosos es un dominio especializado que exige la máxima precisión, experiencia y un estricto cumplimiento de las normas de seguridad internacionales. En Eastern Cargo ofrecemos soluciones logísticas integrales para que sus envíos se muevan de forma segura por aire, mar y tierra.",
        "DGR_SERVICES_TITLE": "Nuestros Servicios de Logística de Mercancías Peligrosas, Químicas y Peligrosas",
        "DGR_FEATURE_1_TITLE": "Clasificación e Identificación:",
        "DGR_FEATURE_1_DESC": "Clasificación precisa de productos químicos y carga peligrosa según las regulaciones de la IATA y locales. Asignamos los números ONU, clases de peligro y grupos de embalaje correctos a cada envío.",
        "DGR_FEATURE_2_TITLE": "Embalaje y Etiquetado Certificados:",
        "DGR_FEATURE_2_DESC": "Todos los artículos son embalados, marcados y etiquetados con materiales conformes a las normativas de DG por personal capacitado para prevenir fugas, derrames y accidentes. El cumplimiento de las normas internacionales es nuestra prioridad para cada modo de transporte.",
        "DGR_FEATURE_3_TITLE": "Documentación y Cumplimiento Regulatorio:",
        "DGR_FEATURE_3_DESC": "Gestionamos la documentación completa —declaraciones de DG, Hojas de Datos de Seguridad (SDS/MSDS), permisos y seguros— asegurando un cumplimiento normativo impecable con la IATA.",
        "DGR_FEATURE_4_TITLE": "Manejo Capacitado y Transporte Seguro:",
        "DGR_FEATURE_4_DESC": "Su carga peligrosa es gestionada por profesionales certificados que utilizan contenedores aprobados para DG.",
        "DGR_FEATURE_5_TITLE": "Soporte Logístico Integral para DG:",
        "DGR_FEATURE_5_DESC": "Servicios de espectro completo desde la evaluación de riesgos y consultoría regulatoria hasta la programación de envíos, entrega y almacenamiento seguro.",
        "DGR_CTA_1": "¿Listo para enviar sus mercancías peligrosas, productos químicos o materiales peligrosos?",
        "DGR_CTA_2": "Contacte a nuestro equipo de logística certificado en DG hoy mismo para obtener una cotización personalizada y orientación experta sobre el cumplimiento global de envíos de DG.",
        "DGR_QUOTE_TITLE": "Obtenga su Cotización Gratuita para el Envío de Mercancías Peligrosas",
        "DGR_QUOTE_SUBTITLE": "Contacte a nuestros expertos en DG hoy para:",
        "DGR_QUOTE_POINT_1": "Consulta gratuita sobre los requisitos de envío de mercancías peligrosas.",
        "DGR_QUOTE_POINT_2": "Asistencia con la documentación para exportaciones de DG desde la India.",
        "DGR_QUOTE_POINT_3": "Precios competitivos para servicios de carga peligrosa en la India.",
        "DGR_QUOTE_POINT_4": "Soporte 24/7 para sus necesidades de logística de mercancías peligrosas.",

        //PROJECT_LOGISTICS
        "PROJECT_LOGISTICS_TITLE": "Logística de Proyectos",
        "PROJECT_LOGISTICS_SUBTITLE": "Soluciones especializadas para carga de proyectos complejos y transporte de equipos pesados",
        "PROJECT_CARGO_SOLUTIONS_TITLE": "Soluciones Integrales para Carga de Proyectos",
        "PROJECT_CARGO_SOLUTIONS_DESC": "Nuestra división de logística de proyectos se especializa en el manejo de envíos complejos, sobredimensionados y de equipo pesado para proyectos industriales, centrales eléctricas, instalaciones de petróleo y gas, y desarrollo de infraestructura. Con décadas de experiencia, aseguramos una coordinación perfecta desde la fábrica hasta el destino final.",
        "OUR_PROJECT_LOGISTICS_SERVICES_TITLE": "Nuestros Servicios de Logística de Proyectos",
        "PROJECT_SERVICE_1_TITLE": "Transporte de Equipo Pesado:",
        "PROJECT_SERVICE_1_DESC": "Manejo especializado de maquinaria, turbinas, generadores y equipo industrial con embalaje a medida y transporte seguro.",
        "PROJECT_SERVICE_2_TITLE": "Soluciones para Carga Sobredimensionada:",
        "PROJECT_SERVICE_2_DESC": "Gestión experta de envíos sobredimensionados que requieren permisos especiales, estudios de ruta y equipo de transporte especializado.",
        "PROJECT_SERVICE_3_TITLE": "Coordinación de Proyectos:",
        "PROJECT_SERVICE_3_DESC": "Gestión integral de proyectos que incluye documentación, despacho de aduanas, seguros y seguimiento en tiempo real.",
        "PROJECT_SERVICE_4_TITLE": "Transporte Multimodal:",
        "PROJECT_SERVICE_4_DESC": "Integración perfecta de los modos de transporte aéreo, marítimo y terrestre para los requisitos complejos de los proyectos.",
        "PROJECT_SERVICE_5_TITLE": "Entrega e Instalación en Obra:",
        "PROJECT_SERVICE_5_DESC": "Coordinación de la entrega en obra, posicionamiento de equipos y servicios de apoyo a la instalación.",
        "INDUSTRIES_WE_SERVE_TITLE": "Industrias a las que Servimos",
        "INDUSTRY_1_TITLE": "Petróleo y Gas",
        "INDUSTRY_1_DESC": "Equipos para oleoductos, maquinaria de perforación y componentes de refinería",
        "INDUSTRY_2_TITLE": "Generación de Energía",
        "INDUSTRY_2_DESC": "Turbinas, generadores, transformadores y equipos para centrales eléctricas",
        "INDUSTRY_3_TITLE": "Manufactura",
        "INDUSTRY_3_DESC": "Líneas de producción, maquinaria industrial y equipos de fabricación",
        "INDUSTRY_4_TITLE": "Infraestructura",
        "INDUSTRY_4_DESC": "Equipos de construcción, componentes de puentes y materiales de infraestructura.",

        //Human Remains
        'HUMAN_REMAINS_TITLE': 'Servicios de Transporte de Restos Humanos',
        'HUMAN_REMAINS_DESC': 'Eastern Cargo Carriers ofrece servicios profesionales y compasivos de transporte de restos humanos con la máxima dignidad y respeto. Nuestro equipo experimentado comprende la naturaleza sensible de estos servicios y se asegura de que cada aspecto del proceso de transporte se maneje con cuidado, profesionalismo y total confidencialidad. Ofrecemos soluciones integrales para el transporte de restos humanos tanto a nivel nacional como internacional, incluyendo toda la documentación necesaria, el despacho de aduanas y el cumplimiento de las normativas.',
        'WHY_CHOOSE_HUMAN_REMAINS_TITLE': '¿Por Qué Elegir Nuestros Servicios de Transporte de Restos Humanos?',
        'HUMAN_REMAINS_FEATURE_1_TITLE': 'Servicio Compasivo:',
        'HUMAN_REMAINS_FEATURE_1_DESC': 'Nuestro equipo proporciona un manejo sensible y respetuoso, con una comprensión total de la naturaleza emocional de estos servicios.',
        'HUMAN_REMAINS_FEATURE_2_TITLE': 'Documentación Completa:',
        'HUMAN_REMAINS_FEATURE_2_DESC': 'Nos encargamos de todo el papeleo necesario, incluyendo certificados de defunción, certificados de embalsamamiento, permisos de tránsito y documentación aduanera.',
        'HUMAN_REMAINS_FEATURE_3_TITLE': 'Experiencia Internacional:',
        'HUMAN_REMAINS_FEATURE_3_DESC': 'Conocimiento especializado de las regulaciones internacionales, los requisitos de las aerolíneas y los protocolos del país de destino para el transporte de restos humanos.',
        'HUMAN_REMAINS_FEATURE_4_TITLE': 'Soporte 24/7:',
        'HUMAN_REMAINS_FEATURE_4_DESC': 'Asistencia y coordinación las 24 horas del día para garantizar servicios de transporte puntuales y dignos.',
        'HUMAN_REMAINS_FEATURE_5_TITLE': 'Cumplimiento Normativo:',
        'HUMAN_REMAINS_FEATURE_5_DESC': 'Cumplimiento total con las regulaciones de la IATA, los requisitos sanitarios internacionales y las regulaciones de importación/exportación del país de destino.',
        'SERVICES_INCLUDED_TITLE': 'Nuestros Servicios Incluyen:',
        'SERVICE_1_TITLE': 'Repatriación Internacional:',
        'SERVICE_1_DESC': 'Transporte internacional completo de restos humanos con toda la documentación necesaria y despacho de aduanas.',
        'SERVICE_2_TITLE': 'Transporte Nacional:',
        'SERVICE_2_DESC': 'Transporte nacional fiable de restos humanos en toda la India con el manejo y la documentación adecuados.',
        'SERVICE_3_TITLE': 'Asistencia con la Documentación:',
        'SERVICE_3_DESC': 'Asistencia completa con toda la documentación requerida, incluyendo certificados de defunción, certificados de embalsamamiento y permisos de tránsito.',
        'SERVICE_4_TITLE': 'Despacho de Aduanas:',
        'SERVICE_4_DESC': 'Servicios expertos de despacho de aduanas para el transporte internacional de restos humanos con pleno cumplimiento normativo.',
        'SERVICE_5_TITLE': 'Coordinación con Aerolíneas:',
        'SERVICE_5_DESC': 'Coordinación directa con las aerolíneas para garantizar el manejo adecuado y el transporte puntual de los restos humanos.'
    },

    fr: {
        // Navigation
        'ABOUT US': 'À PROPOS',
        'OUR SERVICES': 'NOS SERVICES',
        'MORE': 'PLUS',
        'SPECIALIZED SERVICES': 'SERVICES SPÉCIALISÉS',
        'Healthcare Logistics': 'Logistique de Santé',
        'DG Shipments': 'Expéditions DG',
        'Project Logistics': 'Logistique de Projet',
        'Our Team': 'Notre Équipe',
        'Calculator': 'Calculateur',
        'Customer Reviews': 'Avis Clients',
        'CONTACT US': 'CONTACTEZ-NOUS',
        'Have any Questions?': 'Avez-vous des questions?',
        'COMPANY_MAIN': 'EASTERN CARGO',
        'COMPANY_SUB': 'CARRIERS (I) PVT.LTD',
        'EMAIL_INFO': 'info@easterncargo.co.in',
        'EMAIL_LSETH': 'lseth@easterncargo.co.in',
        'PHONE_NO': '+91-22-67539999',
        'LANGUAGE_SELECTOR_TEXT': 'FR',

        // Hero Section
        'Worldwide Logistics': 'Logistique Mondiale',
        'International Air Freight': 'Fret Aérien International',
        'Contact Us': 'Contactez-nous',
        'Get your free quote today': 'Obtenez votre devis gratuit aujourd\'hui',
        'Reliable & Efficient': 'Fiable et Efficace',
        'Multimodal Transport Network': 'Réseau de Transport Multimodal',
        'Our Services': 'Nos Services',
        'Global Trade Solutions': 'Solutions de Commerce Mondial',
        'Ocean Freight Solutions': 'Solutions de Fret Maritime',
        'Get a Quote': 'Obtenir un Devis',
        'Select Service': 'Sélectionner le Service',
        'Air Freight': 'Fret Aérien',
        'Sea Freight': 'Fret Maritime',
        'Land Transport': 'Transport Terrestre',
        'Warehousing': 'Entreposage',
        'Pharma Logistics': 'Logistique Pharmaceutique',
        'DGR Shipments': 'Expéditions DGR',
        'Project Logistics': 'Logistique de Projets',
        'Name': 'Nom',
        'Email': 'Email',
        'Phone': 'Téléphone',
        'Service Type': 'Type de Service',
        'Your Message': 'Votre Message',
        'Enter CAPTCHA': 'Entrez le CAPTCHA',
        'Request A Quote': 'Demander un Devis',
        'WRONG_CAPTCHA': '❌ CAPTCHA incorrect',
        'CORRECT_CAPTCHA': '✅ CAPTCHA vérifié',

        //WHY CHOOSE US
        'WHY CHOOSE US': 'POURQUOI NOUS CHOISIR',
        'Delivering Comprehensive Global Logistics Solutions': 'Livraison de Solutions Logistiques Globales Complètes.',
        'WHAT WE DO': 'CE QUE NOUS FAISONS',
        'OUR AWARD': 'NOTRE RÉCOMPENSE',
        'COMPANY HISTORY': 'HISTOIRE DE L\'ENTREPRISE',
        'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Eastern Cargo est une entreprise indienne indépendante et de propriété privée avec plus de 45 ans d\'expérience fournissant des services intégraux d\'importation et d\'exportation, couvrant le transport aérien, maritime et terrestre, ainsi que le dédouanement expert. Nous livrons des solutions dans de multiples verticales telles que les projets, les produits chimiques, les produits pharmaceutiques, les vêtements, les biens d\'ingénierie, la cargaison liquide, la cargaison dangereuse, la logistique à température contrôlée et le commerce électronique, le tout soutenu par une forte présence pan-indienne.',
        'Warehouse Facility': 'Installation d\'entrepôt',
        'Air Freight Facility': 'Installation de Fret Aérien',
        'Cost Effective Pricing': 'Tarification Rentable',
        'Timely Delivery': 'Livraison en Temps Opportun',
        'Container delivery': 'Livraison de Conteneurs',
        'Best Team Member': 'Meilleur Membre de l\'Équipe',
        'Learn More': 'En Savoir Plus',
        'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Notre entreprise est spécialisée dans la livraison de solutions de transport aérien et maritime sur mesure pour répondre aux besoins uniques de chaque client. Qu\'il s\'agisse de fret international ou de cargaison sensible au temps, nous assurons des services fiables, efficaces et rentables à travers les chaînes d\'approvisionnement mondiales. Nous livrons des solutions dans de multiples verticales telles que les projets, les produits chimiques, les produits pharmaceutiques, les vêtements, les biens d\'ingénierie, la cargaison liquide, la cargaison dangereuse, la logistique à température contrôlée et le commerce électronique, le tout soutenu par une forte présence pan-indienne.',
        'Global Network': 'Réseau Global',
        'Real-time Tracking': 'Suivi en Temps Réel',
        'Customs Expertise': 'Expertise Douanière',
        'Multi-modal Transport': 'Transport Multimodal',
        'Risk Management': 'Gestion des Risques',
        'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.': 'Eastern Cargo a reçu de nombreux prix prestigieux de l\'industrie pour son excellence en matière de transit et de logistique. Notre performance constante et notre dévouement à la qualité nous ont valu la reconnaissance des principales compagnies aériennes, des expéditeurs mondiaux et des agents logistiques de confiance, ce qui consolide notre réputation en tant que partenaire fiable dans les solutions de fret international.',
        'ISO Certified': 'Certifié ISO',
        'Industry Awards': 'Prix de l\'Industrie',
        'Quality Standards': 'Normes de Qualité',
        'Customer Recognition': 'Reconnaissance du Client',
        'AEO certified': 'Certifié OEA',
        'Excellence Certificates': 'Certificats d\'Excellence',

        // Memberships
        'Memberships & Certifications': 'Adhésions et Certifications',
        'Proud members of leading global logistics organizations': 'Fiers membres des principales organisations logistiques mondiales',
        'ISO 9001:2015': 'ISO 9001:2015',
        'AEO Certified': 'Certifié OEA',
        'WCA Member': 'Membre WCA',
        'IATA Agent': 'Agent IATA',
        'FIATA Member': 'Membre FIATA',
        'ACAAI Member': 'Membre ACAAI',
        'MIFFA Member': 'Membre MIFFA',

        // About Section
        'About EASTERN CARGO CARRIERS (I) PVT.LTD': 'À propos d\'EASTERN CARGO CARRIERS (I) PVT.LTD',
        'Our Legacy & Commitment': 'Notre Héritage et Engagement',
        'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.': 'En tant qu\'entreprise indienne fièrement indépendante et privée, Eastern Cargo Carriers (I) Pvt. Ltd. apporte plus de 45 ans d\'expérience dédiée à l\'industrie logistique. Nous nous spécialisons dans la fourniture d\'un service complet "De Bout en Bout" pour nos clients, couvrant tous les aspects des importations et exportations par transport aérien, maritime et terrestre, avec un dédouanement sans problème.',
        'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.': 'Notre présence mondiale est renforcée par notre enregistrement officiel en tant qu\'Opérateur de Transport Multimodal (MTO) auprès de la DG Shipping, Gouvernement de l\'Inde. Cela nous permet d\'offrir une expertise spécialisée dans un large éventail de secteurs, y compris la Cargaison de Projets, les Produits Chimiques, les Pharmaceutiques, les Vêtements, les Biens d\'Ingénierie, la Cargaison Liquide, la Cargaison Dangereuse (Haz), les expéditions à Température Contrôlée et la logistique E-Commerce.',
        'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.': 'Nous nous engageons aux plus hauts standards de qualité, démontrés par notre certification ISO 9001, certification AEO pour un dédouanement optimisé, et notre entrepôt conforme GDP. En tant que membres enregistrés d\'IATA et FIATA, nous adhérons aux meilleures pratiques mondiales.',
        'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.': 'Avec une présence robuste dans toute l\'Inde, nous fournissons des solutions flexibles et puissantes, du traitement de la cargaison à température contrôlée, dangereuse et liquide à l\'organisation de charters aériens et maritimes complets ou partiels. Nos capacités de fret maritime couvrent tout, des conteneurs FCL et LCL au vrac, RORO, levages lourds, équipements spéciaux et autres cargaisons anormales.',

        // Timeline
        'Ecc\'s Group Key Milestones in Aviation and Logistics': 'Jalons Clés du Groupe Ecc en Aviation et Logistique',
        'YEAR_1979': '1979',
        'Custom House Agent': 'Agent en Douane',
        'Established as a CHA': 'Établi comme CHA',
        'CHA_TITLE': 'Agent en Douane (CHA)',
        'CHA_DESC': 'Eastern Cargo Carriers a commencé son voyage en tant qu\'Agent en Douane, fournissant des services essentiels de dédouanement pour les opérations d\'importation et d\'exportation. Cela a marqué la fondation de notre expertise logistique.',
        'CHA_LIST_1': 'Services de dédouanement',
        'CHA_LIST_2': 'Gestion de la documentation',
        'CHA_LIST_3': 'Facilitation d\'importation/exportation',
        'YEAR_1984': '1984',
        'IATA Agent': 'Agent IATA',
        'Leveraging accreditation': 'Exploiter l\'accréditation',
        'IATA_TITLE': 'Accréditation IATA',
        'IATA_DESC': 'Nous avons obtenu l\'accréditation de l\'Association du Transport Aérien International (IATA), nous permettant de fournir des services complets de fret aérien avec une portée mondiale et des pratiques standard de l\'industrie.',
        'IATA_LIST_1': 'Réseau mondial de fret aérien',
        'IATA_LIST_2': 'Conformité aux normes IATA',
        'IATA_LIST_3': 'Opérations de cargaison internationale',
        'YEAR_1989': '1989',
        'Charter Operation': 'Opération de Charter',
        'Initiated first charter': 'Premier charter initié',
        'CHARTER_TITLE': 'Lancement des Opérations de Charter',
        'CHARTER_DESC': 'Nous avons lancé notre division d\'opérations de charter, fournissant des solutions d\'avions dédiées pour les exigences de cargaison urgentes et spécialisées. Cela a considérablement élargi notre portefeuille de services.',
        'CHARTER_LIST_1': 'Charters d\'avions dédiés',
        'CHARTER_LIST_2': 'Solutions de cargaison urgentes',
        'CHARTER_LIST_3': 'Services de transport spécialisés',
        'YEAR_1994': '1994-99',
        'Network Expansion': 'Expansion du Réseau',
        'Achieved Pan-India presence': 'Présence pan-indienne atteinte',
        'NETWORK_TITLE': 'Expansion du Réseau Pan-Indien',
        'NETWORK_DESC': 'Nous avons réussi à étendre nos opérations à travers l\'Inde, établissant un réseau complet de bureaux et de centres de service pour fournir des solutions logistiques à l\'échelle nationale.',
        'NETWORK_LIST_1': 'Présence nationale',
        'NETWORK_LIST_2': 'Plusieurs emplacements de bureau',
        'NETWORK_LIST_3': 'Réseau de service complet',
        'YEAR_2005': '2005-11',
        'GSAs & Consolidation': 'GSAs & Consolidations',
        'Key GSA partnerships': 'Partenariats GSA clés',
        'GSA_TITLE': 'Partenariats GSA et Consolidations',
        'GSA_DESC': 'Nous avons formé des partenariats stratégiques d\'Agent Général des Ventes (GSA) avec les principales compagnies aériennes internationales et lignes maritimes, consolidant notre position de fournisseur de logistique de premier plan.',
        'GSA_LIST_1': 'Partenariats stratégiques avec les compagnies aériennes',
        'GSA_LIST_2': 'Alliances de transport maritime mondial',
        'GSA_LIST_3': 'Capacités de service améliorées',
        'YEAR_2015': '2015-16',
        'Pharma Expertise': 'Expertise Pharmaceutique',
        'Specialized services': 'Services spécialisés',
        'PHARMA_TITLE': 'Expertise en Logistique Pharmaceutique',
        'PHARMA_DESC': 'Nous avons développé une expertise spécialisée en logistique pharmaceutique, y compris le transport à température contrôlée et l\'entreposage conforme aux BPD pour les produits des sciences de la vie.',
        'PHARMA_LIST_1': 'Solutions à température contrôlée',
        'PHARMA_LIST_2': 'Entreposage conforme aux BPD',
        'PHARMA_LIST_3': 'Expertise spécifique à la pharmacie',
        'YEAR_2017': '2017-18',
        'Temp Warehouse': 'Entrepôt Température',
        'Pharma packaging': 'Emballage pharmaceutique',
        'TEMP_WAREHOUSE_TITLE': 'Entrepôt à Température Contrôlée',
        'TEMP_WAREHOUSE_DESC': 'Nous avons établi des installations d\'entreposage dédiées à température contrôlée pour les produits pharmaceutiques, garantissant un stockage et une manipulation appropriés de la cargaison sensible.',
        'TEMP_WAREHOUSE_LIST_1': 'Stockage à température contrôlée',
        'TEMP_WAREHOUSE_LIST_2': 'Services d\'emballage pharmaceutique',
        'TEMP_WAREHOUSE_LIST_3': 'Protocoles d\'assurance qualité',
        'YEAR_2019': '2019-20',
        'Critical Response': 'Réponse Critique',
        'Imported life-saving drugs': 'Médicaments salvateurs importés',
        'CRITICAL_RESPONSE_TITLE': 'Opérations de Réponse Critique',
        'CRITICAL_RESPONSE_DESC': 'Nous avons géré avec succès les opérations de réponse critique pendant la pandémie, important des médicaments salvateurs et des fournitures médicales avec une vitesse et une efficacité sans précédent.',
        'CRITICAL_RESPONSE_LIST_1': 'Fournitures médicales d\'urgence',
        'CRITICAL_RESPONSE_LIST_2': 'Logistique de réponse rapide',
        'CRITICAL_RESPONSE_LIST_3': 'Transport de médicaments salvateurs',
        'YEAR_2020': '2020-21',
        'Governor\'s Award': 'Prix du Gouverneur',
        'For Pharma Exports': 'Pour les Exportations Pharmaceutiques',
        'GOVERNOR_AWARD_TITLE': 'Reconnaissance du Prix du Gouverneur',
        'GOVERNOR_AWARD_DESC': 'Nous avons reçu le prestigieux Prix du Gouverneur pour l\'excellence en matière d\'exportations pharmaceutiques, reconnaissant notre contribution exceptionnelle au secteur de la logistique de la santé.',
        'GOVERNOR_AWARD_LIST_1': 'Excellence dans les exportations pharmaceutiques',
        'GOVERNOR_AWARD_LIST_2': 'Reconnaissance de l\'industrie',
        'GOVERNOR_AWARD_LIST_3': 'Leadership en logistique de la santé',

        // Services
        'Wide variety of logistics services': 'Large variété de services logistiques',
        'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.': 'Notre entreprise de logistique offre une gamme diversifiée de services adaptés pour répondre aux besoins uniques de chaque client. De l\'entreposage et de la distribution à la gestion du transport et à l\'approvisionnement.',
        'Air Freight (Export & Import)': 'Fret Aérien (Exportation et Importation)',
        'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.': 'Avec plus de 40 ans sur le marché, nous avons une forte portée avec une large gamme de transporteurs aériens pour offrir des prix agressifs et des solutions sur mesure.',
        'Ocean Freight (Import & Export)': 'Fret Maritime (Importation et Exportation)',
        'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.': 'Services complets de fret maritime pour tous vos besoins d\'importation et d\'exportation, garantissant une livraison fiable et ponctuelle dans le monde entier.',
        'Customs Brokerage': 'Transit en Douane',
        'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.': 'Nous offrons une gamme de services douaniers à valeur ajoutée pour faire passer vos expéditions en douane rapidement et efficacement.',
        'Warehouse & Distribution': 'Entrepôt & Distribution',
        'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.': 'Pour assurer le bon fonctionnement de votre chaîne d\'approvisionnement, nous offrons des services d\'entreposage et de distribution dédiés et partagés.',
        'Air Charter': 'Charter Aérien',
        'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.': 'Depuis 1989, nous avons fourni des services urgents et complets de Charter de Cargaison Aérienne, gérant les demandes avec une formation approfondie.',
        'Your Pet Pal': 'Votre Compagnon Animal',
        'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.': 'Des chats et chiens aux chevaux, nous avons les connaissances pour gérer et transporter vos animaux de compagnie avec douceur et soin vers leur destination.',
        'Express Logistics': 'Logistique Express',
        'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.': 'Nos services de fret express international assurent une livraison rapide et fiable pour vos expéditions mondiales urgentes.',
        'Unaccompanied Baggage Shipping': 'Expédition de Bagages non Accompagnés',
        'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.': 'L\'expédition de bagages personnels élimine le stress de votre déménagement en gérant les articles en excès avec un soin expert. Nous gérons l\'emballage professionnel, le dédouanement.',

        // Customer Reviews
        'What our clients say': 'Ce que disent nos clients',
        'Trusted experiences shared by our customers': 'Expériences fiables partagées par nos clients.',
        'TESTIMONIAL_1_TITLE': 'Livraison Super Rapide',
        'TESTIMONIAL_1_DESC': 'Eastern Cargo Carriers a fourni un excellent service pour mon envoi. De la collecte à la livraison, tout a été impeccable et à temps. J\'apprécie vraiment leur professionnalisme et leur support client.',
        'TESTIMONIAL_2_TITLE': 'Services Excellents',
        'TESTIMONIAL_2_DESC': 'Entreprise très professionnelle avec des services fiables et sans retard. Chaque envoi est géré en douceur et à temps, me donnant une tranquillité d\'esprit complète. Vraiment l\'un des meilleurs choix pour des solutions de fret fiables.',
        'TESTIMONIAL_3_TITLE': 'Partenaire Fiable',
        'TESTIMONIAL_3_DESC': 'Eastern Cargo Carriers est devenu notre partenaire de confiance. Leur ponctualité, leur professionnalisme et leur fiabilité garantissent que chaque livraison est traitée avec soin et toujours à temps.',
        'TESTIMONIAL_4_TITLE': 'Abordable et Sûr',
        'TESTIMONIAL_4_DESC': 'Eastern Cargo Carriers offre le moyen le plus économique et le plus sûr d\'envoyer des envois depuis les EAU. Leur ponctualité, leur professionnalisme et leur fiabilité rendent l\'ensemble du processus fluide et sans stress.',
        'TESTIMONIAL_5_TITLE': 'Support Exceptionnel',
        'TESTIMONIAL_5_DESC': 'Eastern Cargo Carriers m\'a impressionné avec leur équipe de support professionnel. Ils ont fourni des mises à jour en temps opportun, ont traité chaque requête avec soin et ont assuré que mon envoi est arrivé ponctuellement et sans problèmes.',
        'TESTIMONIAL_6_TITLE': 'Fiable depuis des Années',
        'TESTIMONIAL_6_DESC': 'Nous nous fions à Eastern Cargo Carriers depuis des années, et leur constance en matière de ponctualité, de professionnalisme et de service fiable en a fait notre premier choix pour chaque envoi.',

        // Calculator
        'Smart Cargo Calculator': 'Calculateur de Cargaison Intelligent',
        'Centimeters (CM)': 'Centimètres (CM)',
        'Inches (IN)': 'Pouces (IN)',
        'Package Dimensions': 'Dimensions du Colis',
        '+ Add Package': '+ Ajouter un Colis',
        'Reset': 'Réinitialiser',
        'Calculate': 'Calculer',

        // Career/Contact Forms
        'Join Our Team': 'Rejoindre Notre Équipe',
        'Build your career with Eastern Cargo Carriers – explore exciting opportunities today.': 'Construisez votre carrière avec Eastern Cargo Carriers – explorez des opportunités passionnantes aujourd\'hui.',
        'Upload Resume': 'Télécharger le CV',
        'Your Message (Optional)': 'Votre Message (Facultatif)',
        'Submit Application': 'Soumettre la Candidature',
        'Request your free logistics quote today and experience hassle-free shipping.': 'Demandez votre devis logistique gratuit aujourd\'hui et vivez une expérience d\'expédition sans tracas.',

        // Footer
        'FOOTER_HEADING': 'Eastern Cargo Carriers (I) Pvt.Ltd.',
        'FOOTER_ADDRESS': 'Unité #25/26/27, Adarsh Industrial Estate, Sahar Road, Chakala, Andheri (East), Mumbai – 400 099',
        'Quick Links': 'Liens Rapides',
        'About Us': 'À Propos de Nous',
        'Careers': 'Carrières',
        'Get a Quote': 'Obtenir un Devis',
        'Our Team': 'Notre Équipe',
        'Our Services': 'Nos Services',
        'Client Reviews': 'Avis Clients',
        'Specialized Services': 'Services Spécialisés',
        'Express Logistics': 'Logistique Express',
        'Healthcare Logistics': 'Logistique de Santé',
        'DG Shipments': 'Expéditions DG',
        'Project Logistics': 'Logistique de Projets',
        'Find Us': 'Nous Trouver',
        'Follow us :': 'Suivez-nous :',
        'COPYRIGHT': '© Copyright 2025. Tous Droits Réservés par Eastern Cargo Carriers (I) Pvt.Ltd',
        'Select Language': 'Sélectionner la Langue',
        'CLOSE_MODAL': '×',
        'English': 'Anglais',
        'Spanish': 'Espagnol',
        'French': 'Français',
        'German': 'Allemand',
        'Chinese': 'Chinois',
        'Japanese': 'Japonais',

        //Menu
        'ABOUT US': 'À PROPOS',
        'OUR SERVICES': 'NOS SERVICES',
        'MORE': 'PLUS',
        'SPECIALIZED SERVICES': 'SERVICES SPÉCIALISÉS',
        'Healthcare Logistics': 'Logistique de Santé',
        'DG Shipments': 'Expéditions DG',
        'Project Logistics': 'Logistique de Projet',
        'Our Team': 'Notre Équipe',
        'Calculator': 'Calculateur',
        'Customer Reviews': 'Avis Clients',
        'CONTACT US': 'CONTACTEZ-NOUS',
        'Have any Questions?': 'Avez-vous des questions?',

        //Air Freight
        "Air Freight (Export & Import Services)": "Fret Aérien (Services d'Exportation et d'Importation)",
        "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.": "Avec plus de 40 ans de leadership sur le marché indien, Eastern Cargo Carriers (I) Pvt. Ltd. se distingue par sa portée étendue et ses partenariats solides avec des transporteurs aériens régionaux et internationaux. Nous offrons également à nos clients un réseau mondial d'agents robuste, permettant de véritables solutions de fret aérien de porte à porte, de l'enlèvement à l'origine à la livraison finale à destination. Cette combinaison inégalée nous permet de proposer un service fiable et rapide, des tarifs très compétitifs et un contrôle total vers toutes les principales destinations mondiales. Que vous ayez besoin d'un transport aérien standard ou d'une logistique de fret spécialisée et sensible, nos solutions sur mesure garantissent que votre marchandise se déplace avec rapidité, sécurité et efficacité à chaque étape du processus.",
        "Why Choose Our Air Freight Services?": "Pourquoi Choisir Nos Services de Fret Aérien ?",
        "Aggressive, Competitive Rates:": "Tarifs Agressifs et Compétitifs :",
        " Leverage our airline relationships for the best pricing to key global hubs.": "Profitez de nos relations avec les compagnies aériennes pour obtenir les meilleurs prix vers les principaux hubs mondiaux.",
        "Faster Transit Times:": "Délais de Transit Plus Rapides :",
        "Priority access ensures your cargo arrives on schedule—every time.": "L'accès prioritaire garantit que votre cargaison arrive à temps, à chaque fois.",
        "Advanced Cold Chain & Temperature Control:": "Chaîne du Froid et Contrôle de Température Avancés :",
        "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.": "Nous gérons avec expertise les expéditions en conteneurs réfrigérés, sensibles à la température et actifs (Envirotainer).",
        "Specialized Cargo Handling:": "Manutention de Fret Spécialisé :",
        "From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.": "Des DGR (marchandises dangereuses) aux objets de valeur, en passant par les animaux de compagnie/vivants et les dépouilles mortelles, notre équipe s'occupe de tout avec soin et conformité.",
        "End-to-End Service:": "Service de Bout en Bout :",
        "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.": "Recevez des solutions complètes incluant l'enlèvement/livraison, l'emballage, l'étiquetage, la documentation, l'assurance et le dédouanement.",
        "Additional Capabilities": "Capacités Supplémentaires",
        "Cargo consolidation for cost efficiency to key destinations.": "Consolidation de fret pour une meilleure rentabilité vers les destinations clés.",
        "Expert handling of personal effects, household goods, and chartered flight operations.": "Manutention experte des effets personnels, des articles ménagers et des opérations de vols affrétés.",
        "Full spectrum of value-added services with and expert support at every step.": "Une gamme complète de services à valeur ajoutée avec un soutien expert à chaque étape.",

        //OCEAN_FREIGHT
        "OCEAN_FREIGHT_TITLE": "Fret Maritime (Services d'Importation et d'Exportation)",
        "OCEAN_FREIGHT_DESC": "La bonne volonté et les partenariats solides que nous avons cultivés avec les grandes compagnies maritimes au fil des ans nous permettent de fournir des solutions complètes de fret maritime qui respectent des délais stricts pour les opérations d'exportation et d'importation. Notre expertise couvre l'ensemble du spectre de la logistique maritime, des expéditions conteneurisées standard aux cargaisons de projets complexes, soutenues par d'excellents agents à l'étranger qui assurent une livraison porte-à-porte transparente dans le monde entier.",
        "WHY_CHOOSE_OCEAN_FREIGHT_TITLE": "Pourquoi Choisir Nos Services de Fret Maritime ?",
        "OCEAN_FREIGHT_FEATURE_1_TITLE": "Solutions Complètes FCL & LCL :",
        "OCEAN_FREIGHT_FEATURE_1_DESC": "Options de réservation flexibles avec des tarifs compétitifs grâce à nos partenariats établis avec les compagnies maritimes pour les conteneurs complets et consolidés.",
        "OCEAN_FREIGHT_FEATURE_2_TITLE": "Expertise en Fret Spécialisé :",
        "OCEAN_FREIGHT_FEATURE_2_DESC": "Manutention experte de l'ODC (cargaison de dimensions spéciales), des cargaisons de projet, des matières dangereuses et du fret réfrigéré avec des solutions à température contrôlée.",
        "OCEAN_FREIGHT_FEATURE_3_TITLE": "Intégration de Service de Bout en Bout :",
        "OCEAN_FREIGHT_FEATURE_3_DESC": "Gestion logistique complète incluant le dédouanement, l'emballage, la palettisation, l'assurance maritime et la gestion DDU/DDP.",
        "OCEAN_FREIGHT_FEATURE_4_TITLE": "Réseau Mondial et Spécialisation des Routes Commerciales :",
        "OCEAN_FREIGHT_FEATURE_4_DESC": "Un vaste réseau d'agents à l'étranger assure un service fiable sur des routes commerciales spécialisées avec une expertise locale.",
        "OCEAN_FREIGHT_FEATURE_5_TITLE": "Services Maritimes à Valeur Ajoutée :",
        "OCEAN_FREIGHT_FEATURE_5_DESC": "Support complet incluant la consolidation/déconsolidation, l'entreposage, la distribution, le transport et la manutention des effets personnels pour une gestion complète de la chaîne d'approvisionnement.",

        //CUSTOMS_BROKERAGE
        "CUSTOMS_BROKERAGE_TITLE": "Services de Courtage en Douane",
        "CUSTOMS_BROKERAGE_DESC": "Naviguer dans les réglementations complexes du commerce international nécessite des services experts de courtage en douane qui assurent un dédouanement rapide et conforme de vos expéditions à l'exportation. En tant que courtiers en douane certifiés OEA avec une expertise réglementaire approfondie, nous rationalisons l'ensemble du processus douanier, minimisons les retards et optimisons les coûts des droits de douane pour les entreprises de tous les secteurs.",
        "WHY_CHOOSE_CUSTOMS_BROKERAGE_TITLE": "Pourquoi Choisir Nos Services de Courtage en Douane ?",
        "CUSTOMS_BROKERAGE_FEATURE_1_TITLE": "Expertise Certifiée OEA :",
        "CUSTOMS_BROKERAGE_FEATURE_1_DESC": "Le statut d'Opérateur Économique Agréé garantit un traitement douanier plus rapide et fiable avec des inspections réduites.",
        "CUSTOMS_BROKERAGE_FEATURE_2_TITLE": "Conformité Réglementaire Complète :",
        "CUSTOMS_BROKERAGE_FEATURE_2_DESC": "Gestion complète de la documentation, classification tarifaire et respect de toutes les réglementations d'import/export.",
        "CUSTOMS_BROKERAGE_FEATURE_3_TITLE": "Optimisation des Droits et Coûts :",
        "CUSTOMS_BROKERAGE_FEATURE_3_DESC": "Classification tarifaire stratégique et utilisation des accords commerciaux pour minimiser les droits de douane et les frais.",
        "CUSTOMS_BROKERAGE_FEATURE_4_TITLE": "Manutention de Fret Spécialisé :",
        "CUSTOMS_BROKERAGE_FEATURE_4_DESC": "Dédouanement expert des matières dangereuses, des marchandises réglementées et des envois de grande valeur en conformité avec la réglementation.",
        "CUSTOMS_BROKERAGE_FEATURE_5_TITLE": "Soutien de Bout en Bout :",
        "CUSTOMS_BROKERAGE_FEATURE_5_DESC": "Service complet de la préparation de la documentation à la livraison finale.",

        //WAREHOUSE
        "WAREHOUSE_TITLE": "Services d'Entreposage et de Distribution",
        "WAREHOUSE_DESC": "Chez Eastern Cargo Carriers (I) Pvt.LTD, nous veillons à ce que votre chaîne d'approvisionnement fonctionne de manière transparente en fournissant des services d'entreposage et de distribution dédiés et partagés, adaptés à vos besoins. Notre équipe d'associés expérimentés offre un soutien solide à chaque étape du transport, gérant efficacement vos marchandises du stockage à la livraison finale. Que vous ayez besoin d'un stockage à court ou à long terme, nous proposons des installations sécurisées et organisées, équipées pour la palettisation, l'emballage, le filmage rétractable et l'étiquetage. Notre réseau d'entreposage stratégique permet un accès rapide et fiable aux principales routes commerciales, garantissant que vos produits parviennent aux clients à temps, à chaque fois. Nous gérons également des exigences spécialisées telles que la fumigation pour maintenir les normes de sécurité des produits et nous conformer aux réglementations internationales.",

        //AIR_CHARTER
        "AIR_CHARTER_TITLE": "Services de Fret Aérien Charter",
        "AIR_CHARTER_DESC": "Depuis 1989, Eastern Cargo Carriers se spécialise dans l'affrètement de fret aérien urgent et complet pour les expéditions urgentes et spécialisées. Notre équipe dédiée est experte dans la manutention de cargaisons complexes — des produits pharmaceutiques vitaux pendant la pandémie aux équipements industriels surdimensionnés — garantissant que votre fret est livré avec une vitesse, une sécurité et une flexibilité inégalées. Nous offrons des options d'affrètement complet et partiel, offrant un contrôle total sur le processus de transport, avec une gestion de bout en bout incluant le positionnement de l'aéronef, la manutention, la coordination douanière et la livraison d'aéroport à aéroport dans les principaux aéroports indiens.",
        "WHY_CHOOSE_AIR_CHARTER_TITLE": "Pourquoi Choisir Nos Services de Fret Aérien Charter ?",
        "AIR_CHARTER_FEATURE_1_TITLE": "Options d'Affrètement Personnalisées :",
        "AIR_CHARTER_FEATURE_1_DESC": "Affrètements complets ou partiels, aller simple ou aller-retour, adaptés à votre emploi du temps et aux exigences de votre cargaison.",
        "AIR_CHARTER_FEATURE_2_TITLE": "Expertise en Logistique d'Urgence :",
        "AIR_CHARTER_FEATURE_2_DESC": "Expérience avérée dans l'exécution de missions critiques — telles que l'exportation et l'importation de produits pharmaceutiques liés à la pandémie — dans des délais stricts.",
        "AIR_CHARTER_FEATURE_3_TITLE": "Manutention Complète :",
        "AIR_CHARTER_FEATURE_3_DESC": "Gestion complète de l'affrètement, du positionnement de l'aéronef au chargement spécialisé, en passant par le dédouanement et la livraison, conformément aux directives de la DGCA.",
        "AIR_CHARTER_FEATURE_4_TITLE": "Accès Stratégique aux Aéroports :",
        "AIR_CHARTER_FEATURE_4_DESC": "Opérations dans tous les principaux aéroports douaniers indiens, garantissant une rotation rapide et une portée maximale.",

        //PET_PAL
        "PET_PAL_TITLE": "Votre Compagnon Animal : Transport d'Animaux Vivants",
        "PET_PAL_DESC": "Qu'il s'agisse de votre chat ou chien bien-aimé, ou même de chevaux et d'éléphants, Eastern Cargo Carriers veille à ce que chaque animal voyage avec le plus grand soin. Nos installations spécialisées, nos véhicules climatisés et notre équipe formée à la manipulation des animaux rationalisent les expéditions d'animaux vivants à l'arrivée et au départ. Nous utilisons également les meilleures pratiques pour minimiser le stress du vol, afin que votre animal arrive calme et confortable.",
        "WHY_CHOOSE_PET_PAL_TITLE": "Pourquoi Choisir Votre Compagnon Animal ?",
        "PET_PAL_FEATURE_1_TITLE": "Manipulation Experte des Animaux et Soins en Vol :",
        "PET_PAL_FEATURE_1_DESC": "Le personnel formé suit la Réglementation sur les Animaux Vivants de l'IATA, gérant le chargement, les réglages de l'environnement en vol et la coordination de l'équipage pour le bien-être des animaux.",
        "PET_PAL_FEATURE_2_TITLE": "Conformité DGCA :",
        "PET_PAL_FEATURE_2_DESC": "Certificats de santé complets, permis d'import/export et autorisations de quarantaine organisés par les Services de Quarantaine et de Certification Animale dans les principaux aéroports indiens.",
        "PET_PAL_FEATURE_3_TITLE": "Conteneurs et Étiquetage Conformes à l'IATA :",
        "PET_PAL_FEATURE_3_DESC": "Conteneurs sécurisés et ventilés avec un rembourrage adéquat, un drainage et un étiquetage « Animaux Vivants » en anglais et dans la langue locale.",
        "PET_PAL_FEATURE_4_TITLE": "Plans de Soins Personnalisés :",
        "PET_PAL_FEATURE_4_DESC": "Protocoles personnalisés d'alimentation, d'exercice et de sédation pour réduire le stress, avec des coordonnées d'urgence 24 heures sur 24 sur la Lettre de Transport Aérien.",
        "PET_PAL_FEATURE_5_TITLE": "Service Mondial :",
        "PET_PAL_FEATURE_5_DESC": "Un réseau d'agents robuste assure un enlèvement et une livraison sécurisés à domicile, à l'aéroport ou dans un établissement vétérinaire, garantissant une continuité des soins sans faille.",

        //EXPRESS_CARGO
        "EXPRESS_CARGO_TITLE": "Transport de Fret Express Urgent",
        "EXPRESS_CARGO_DESC": "Express Cargo est notre service premium pour le transport d'envois urgents à une vitesse et une efficacité optimales le long de la chaîne d'approvisionnement, sous surveillance experte. Des documents urgents et des marchandises précieuses aux produits pharmaceutiques vitaux, en passant par les échantillons de sang pour analyse, les pièces de rechange d'aéronefs et les composants AOG (Aircraft on Ground), nous gérons une gamme variée de fret express avec des fenêtres de service rapides. Notre réseau multimodal combine le transport aérien, routier et spécialisé pour garantir que vos marchandises atteignent leur destination dans un délai de 24 à 72 heures pour les besoins critiques.",
        "EXPRESS_CARGO_FEATURES_TITLE": "Options de Livraison et Caractéristiques du Service",
        "EXPRESS_CARGO_FEATURE_1_TITLE": "Express Porte-à-Porte :",
        "EXPRESS_CARGO_FEATURE_1_DESC": "Service complet d'enlèvement et de livraison depuis l'origine jusqu'à la destination finale.",
        "EXPRESS_CARGO_FEATURE_2_TITLE": "Express d'Aéroport à Aéroport :",
        "EXPRESS_CARGO_FEATURE_2_DESC": "Service rapide de terminal à terminal pour le fret aérien avec une manutention réduite et un dédouanement accéléré.",

        //PERSONAL_EFFECTS
        "PERSONAL_EFFECTS_TITLE": "Transport d'Effets Personnels",
        "PERSONAL_EFFECTS_DESC": "Nous sommes spécialisés dans le transport de vos effets personnels en toute sécurité et à un prix abordable. Lorsque les limites de bagages des compagnies aériennes et les frais d'excédent menacent votre déménagement, Eastern Cargo Carriers propose des solutions de bagages non accompagnés sans faille. En tirant parti de notre réseau mondial d'agents, nous gérons l'emballage, les douanes et la livraison de porte à aéroport et de porte à porte de vos biens ménagers afin que vous puissiez vous concentrer sur votre installation, et non sur la logistique d'expédition.",
        "WHY_CHOOSE_PERSONAL_EFFECTS_TITLE": "Pourquoi Choisir Notre Transport d'Effets Personnels ?",
        "PERSONAL_EFFECTS_FEATURE_1_TITLE": "Gestion des Excédents de Bagages :",
        "PERSONAL_EFFECTS_FEATURE_1_DESC": "Consolidez et expédiez les articles dépassant les franchises des compagnies aériennes en tant que bagages non accompagnés, éliminant ainsi les frais élevés.",
        "PERSONAL_EFFECTS_FEATURE_2_TITLE": "Couverture Porte-à-Porte :",
        "PERSONAL_EFFECTS_FEATURE_2_DESC": "Enlèvement sécurisé à votre domicile et livraison à n'importe quelle adresse dans le monde via notre vaste réseau d'agents.",
        "PERSONAL_EFFECTS_FEATURE_3_TITLE": "Emballage et Étiquetage Professionnels :",
        "PERSONAL_EFFECTS_FEATURE_3_DESC": "Mise en caisse, rembourrage et étiquetage experts pour protéger les marchandises fragiles en transit.",
        "PERSONAL_EFFECTS_FEATURE_4_TITLE": "Gestion des Douanes et de la Documentation :",
        "PERSONAL_EFFECTS_FEATURE_4_DESC": "Formalités et dédouanements complets pour prévenir les retards et assurer la conformité réglementaire.",
        "PERSONAL_EFFECTS_FEATURE_5_TITLE": "Soutien de Bout en Bout :",
        "PERSONAL_EFFECTS_FEATURE_5_DESC": "Mises à jour de l'expédition en direct et service client dédié de l'origine à la livraison finale.",

        //HEALTHCARE_LOGISTICS
        "HEALTHCARE_LOGISTICS_TITLE": "Logistique de la Santé",
        "HEALTHCARE_LOGISTICS_SUBTITLE": "Fournir la santé avec précision et soin depuis 1987",
        "HEALTHCARE_TRUST_TITLE": "Une Logistique de la Santé de Confiance",
        "HEALTHCARE_TRUST_DESC": "Dans le domaine de la santé, chaque envoi est critique. Chez Eastern Cargo, nous comprenons que des vies peuvent dépendre de la livraison sûre, rapide et précise de vos produits médicaux. C'est pourquoi nous fournissons des solutions logistiques spécialisées conçues pour les besoins uniques de l'industrie de la santé et des sciences de la vie.",
        "HEALTHCARE_FEATURE_1_TITLE": "Transport à Température Contrôlée :",
        "HEALTHCARE_FEATURE_1_DESC": "Emballages validés et solutions de chaîne du froid pour les envois congelés, réfrigérés et à température ambiante contrôlée.",
        "HEALTHCARE_FEATURE_2_TITLE": "Livraisons Urgentes :",
        "HEALTHCARE_FEATURE_2_DESC": "Traitement prioritaire pour les envois urgents, avec des options de livraison le jour même et au prochain vol.",
        "HEALTHCARE_FEATURE_3_TITLE": "Conformité Réglementaire :",
        "HEALTHCARE_FEATURE_3_DESC": "Assistance pour les réglementations commerciales, douanières et industrielles.",
        "HEALTHCARE_FEATURE_4_TITLE": "Manutention d'Échantillons et d'Équipements :",
        "HEALTHCARE_FEATURE_4_DESC": "Des échantillons de diagnostic et des kits d'essais cliniques aux instruments chirurgicaux et produits pharmaceutiques.",
        "WHY_CHOOSE_HEALTHCARE_TITLE": "Pourquoi les Leaders de la Santé Choisissent Eastern Cargo :",
        "WHY_CHOOSE_HEALTHCARE_POINT_1": "✓ Des spécialistes dédiés à la logistique de la santé.",
        "WHY_CHOOSE_HEALTHCARE_POINT_2": "✓ Une portée nationale et internationale avec des solutions multimodales.",
        "WHY_CHOOSE_HEALTHCARE_POINT_3": "✓ Un soutien opérationnel 24/7 et une planification d'urgence.",
        "WHY_CHOOSE_HEALTHCARE_POINT_4": "✓ Des protocoles de chaîne de possession sécurisés pour les envois sensibles.",
        "HEALTHCARE_CLOSING_1": "Lorsque la précision et la fiabilité comptent le plus, choisissez Eastern Cargo.",
        "HEALTHCARE_CLOSING_2": "Contactez dès aujourd'hui notre équipe de logistique de la santé pour discuter de vos besoins.",
        "PASSION_TITLE": "Une Passion pour les Envois Urgents",
        "PASSION_DESC": "Avec une expérience dans la gestion des envois urgents depuis 1987, nous apportons une expertise inégalée à la logistique pharmaceutique. Notre équipe est reconnue pour sa gestion réussie de produits des sciences de la vie de grande valeur, y compris les envois d'essais cliniques, les lancements de nouveaux produits et les livraisons vers des territoires spéciaux et difficiles.",
        "PASSION_FEATURE_1_TITLE": "Opérations Axées sur la Pharmacie :",
        "PASSION_FEATURE_1_DESC": "Une équipe dédiée et spécifiquement formée aux nuances de la manipulation de tous les types de produits des sciences de la vie.",
        "PASSION_FEATURE_2_TITLE": "Qualité et Conformité :",
        "PASSION_FEATURE_2_DESC": "Un engagement envers la gestion de la qualité, l'excellence opérationnelle et des capacités douanières supérieures garantit que vos envois respectent toutes les normes réglementaires.",
        "PASSION_FEATURE_3_TITLE": "Solutions à Température Contrôlée :",
        "PASSION_FEATURE_3_DESC": "Nous fournissons des solutions pharmaceutiques actives et passives pour maintenir une intégrité thermique stricte de votre cargaison.",
        "PASSION_FEATURE_4_TITLE": "Relations Établies avec les Transporteurs :",
        "PASSION_FEATURE_4_DESC": "Plus de 30 ans de partenariats solides avec les compagnies aériennes et les compagnies maritimes, garantissant fiabilité, priorité et confort pour le client.",
        "TEMP_SOLUTIONS_TITLE": "Nos Solutions à Température Contrôlée",
        "ENVIROTAINERS_TITLE": "Envirotainers (Actifs)",
        "ENVIROTAINERS_DESC": "Nous fournissons des solutions de conteneurs actifs de pointe, telles que l'Envirotainer RKN e1 et RAP e2, qui utilisent un refroidissement par compresseur et un chauffage électrique pour maintenir des températures précises des produits entre +2°C et +8°C ou +15°C et +25°C, quelles que soient les conditions ambiantes.",
        "THERMAL_BLANKETS_TITLE": "Couvertures Thermiques (Passives)",
        "THERMAL_BLANKETS_DESC": "Pour éviter les pics de température dus à la lumière directe du soleil ou aux conditions ambiantes, nous enveloppons toutes les palettes sensibles à la température dans des couvertures thermiques de haute qualité. Cela maintient la plage de température requise pendant le transport, garantissant que les médicaments restent efficaces et sûrs à utiliser.",
        "COOL_BOXES_TITLE": "Boîtes Réfrigérées (Passives)",
        "COOL_BOXES_DESC": "Pour les produits nécessitant un contrôle de température plus strict, nous utilisons des boîtes réfrigérées spécialisées. Celles-ci sont un composant important de l'emballage pharmaceutique, spécifiquement conçues pour maintenir la température de produits sensibles comme les vaccins, l'insuline et les produits sanguins pendant le transport et le stockage.",

        //DGR
        "DGR_TITLE": "Expéditions de Marchandises Dangereuses",
        "DGR_SUBTITLE": "Marchandises Dangereuses, Chimiques et Expéditions à Risques – Solutions Logistiques Expertes",
        "DGR_DESC": "Le transport de marchandises dangereuses (MD), de produits chimiques et de matières dangereuses est un domaine spécialisé, exigeant la plus grande précision, une expertise pointue et une conformité stricte avec les normes de sécurité internationales. Chez Eastern Cargo, nous proposons des solutions logistiques complètes pour les MD afin que vos expéditions soient transportées en toute sécurité par air, mer et route.",
        "DGR_SERVICES_TITLE": "Nos Services Logistiques pour Marchandises Dangereuses, Chimiques et à Risques",
        "DGR_FEATURE_1_TITLE": "Classification et Identification :",
        "DGR_FEATURE_1_DESC": "Classification précise des produits chimiques et des cargaisons dangereuses conformément aux réglementations de l'IATA et locales. Nous attribuons les numéros ONU, les classes de danger et les groupes d'emballage corrects à chaque envoi.",
        "DGR_FEATURE_2_TITLE": "Emballage et Étiquetage Certifiés :",
        "DGR_FEATURE_2_DESC": "Tous les articles sont emballés, marqués et étiquetés avec des matériaux conformes aux normes MD par du personnel qualifié pour prévenir les fuites, les déversements et les accidents. La conformité aux normes internationales est notre priorité pour chaque mode de transport.",
        "DGR_FEATURE_3_TITLE": "Documentation et Conformité Réglementaire :",
        "DGR_FEATURE_3_DESC": "Nous gérons l'ensemble de la documentation — déclarations MD, Fiches de Données de Sécurité (FDS/MSDS), permis et assurances — garantissant une adhésion réglementaire sans faille avec l'IATA.",
        "DGR_FEATURE_4_TITLE": "Manutention par du Personnel Formé et Transport Sécurisé :",
        "DGR_FEATURE_4_DESC": "Votre cargaison dangereuse est gérée par des professionnels certifiés utilisant des conteneurs approuvés pour les MD.",
        "DGR_FEATURE_5_TITLE": "Soutien Logistique Complet pour les MD :",
        "DGR_FEATURE_5_DESC": "Services complets allant de l'évaluation des risques et du conseil réglementaire à la planification des expéditions, la livraison et l'entreposage sécurisé.",
        "DGR_CTA_1": "Prêt à expédier vos marchandises dangereuses, produits chimiques ou matières dangereuses ?",
        "DGR_CTA_2": "Contactez dès aujourd'hui notre équipe logistique certifiée MD pour un devis personnalisé et des conseils d'experts sur la conformité mondiale des expéditions de MD.",
        "DGR_QUOTE_TITLE": "Obtenez Votre Devis Gratuit pour l'Expédition de Marchandises Dangereuses",
        "DGR_QUOTE_SUBTITLE": "Contactez nos experts MD dès aujourd'hui pour :",
        "DGR_QUOTE_POINT_1": "Consultation gratuite sur les exigences d'expédition de marchandises dangereuses.",
        "DGR_QUOTE_POINT_2": "Aide à la documentation pour les exportations de MD depuis l'Inde.",
        "DGR_QUOTE_POINT_3": "Tarifs compétitifs pour les services de fret dangereux en Inde.",
        "DGR_QUOTE_POINT_4": "Assistance 24/7 pour vos besoins logistiques en marchandises dangereuses.",

        //PROJECT_LOGISTICS
        "PROJECT_LOGISTICS_TITLE": "Logistique de Projet",
        "PROJECT_LOGISTICS_SUBTITLE": "Solutions spécialisées pour le transport de cargaisons de projet complexes et d'équipements lourds",
        "PROJECT_CARGO_SOLUTIONS_TITLE": "Solutions Complètes pour Cargaisons de Projet",
        "PROJECT_CARGO_SOLUTIONS_DESC": "Notre division de logistique de projet est spécialisée dans la manutention d'expéditions complexes, surdimensionnées et d'équipements lourds pour des projets industriels, des centrales électriques, des installations pétrolières et gazières, et le développement d'infrastructures. Avec des décennies d'expérience, nous assurons une coordination sans faille de l'usine à la destination finale.",
        "OUR_PROJECT_LOGISTICS_SERVICES_TITLE": "Nos Services de Logistique de Projet",
        "PROJECT_SERVICE_1_TITLE": "Transport d'Équipements Lourds :",
        "PROJECT_SERVICE_1_DESC": "Manutention spécialisée de machines, turbines, générateurs et équipements industriels avec emballage sur mesure et transport sécurisé.",
        "PROJECT_SERVICE_2_TITLE": "Solutions pour Cargaisons Hors Gabarit :",
        "PROJECT_SERVICE_2_DESC": "Gestion experte des expéditions surdimensionnées nécessitant des permis spéciaux, des études d'itinéraire et des équipements de transport spécialisés.",
        "PROJECT_SERVICE_3_TITLE": "Coordination de Projet :",
        "PROJECT_SERVICE_3_DESC": "Gestion de projet complète incluant la documentation, le dédouanement, l'assurance et le suivi en temps réel.",
        "PROJECT_SERVICE_4_TITLE": "Transport Multimodal :",
        "PROJECT_SERVICE_4_DESC": "Intégration transparente des modes de transport aérien, maritime et terrestre pour les exigences complexes des projets.",
        "PROJECT_SERVICE_5_TITLE": "Livraison et Installation sur Site :",
        "PROJECT_SERVICE_5_DESC": "Coordination de la livraison sur site, positionnement des équipements et services de soutien à l'installation.",
        "INDUSTRIES_WE_SERVE_TITLE": "Industries que Nous Servons",
        "INDUSTRY_1_TITLE": "Pétrole et Gaz",
        "INDUSTRY_1_DESC": "Équipements de pipeline, machines de forage et composants de raffinerie",
        "INDUSTRY_2_TITLE": "Production d'Énergie",
        "INDUSTRY_2_DESC": "Turbines, générateurs, transformateurs et équipements de centrale électrique",
        "INDUSTRY_3_TITLE": "Fabrication",
        "INDUSTRY_3_DESC": "Lignes de production, machines industrielles et équipements de fabrication",
        "INDUSTRY_4_TITLE": "Infrastructure",
        "INDUSTRY_4_DESC": "Équipements de construction, composants de ponts et matériaux d'infrastructure.",

        //Human Remains
        'HUMAN_REMAINS_TITLE': 'Services de Transport de Dépouilles Mortelles',
        'HUMAN_REMAINS_DESC': 'Eastern Cargo Carriers fournit des services professionnels et compatissants de transport de dépouilles mortelles avec la plus grande dignité et le plus grand respect. Notre équipe expérimentée comprend la nature sensible de ces services et veille à ce que chaque aspect du processus de transport soit traité avec soin, professionnalisme et une confidentialité absolue. Nous proposons des solutions complètes pour le transport de dépouilles mortelles, tant au niveau national qu\'international, y compris toute la documentation nécessaire, le dédouanement et la conformité réglementaire.',
        'WHY_CHOOSE_HUMAN_REMAINS_TITLE': 'Pourquoi Choisir Nos Services de Transport de Dépouilles Mortelles ?',
        'HUMAN_REMAINS_FEATURE_1_TITLE': 'Service Compatissant :',
        'HUMAN_REMAINS_FEATURE_1_DESC': 'Notre équipe assure une manipulation sensible et respectueuse, avec une compréhension totale de la nature émotionnelle de ces services.',
        'HUMAN_REMAINS_FEATURE_2_TITLE': 'Documentation Complète :',
        'HUMAN_REMAINS_FEATURE_2_DESC': 'Nous nous occupons de tous les documents nécessaires, y compris les certificats de décès, les certificats d\'embaumement, les permis de transport et les documents douaniers.',
        'HUMAN_REMAINS_FEATURE_3_TITLE': 'Expertise Internationale :',
        'HUMAN_REMAINS_FEATURE_3_DESC': 'Connaissance spécialisée des réglementations internationales, des exigences des compagnies aériennes et des protocoles du pays de destination pour le transport de dépouilles mortelles.',
        'HUMAN_REMAINS_FEATURE_4_TITLE': 'Assistance 24/7 :',
        'HUMAN_REMAINS_FEATURE_4_DESC': 'Assistance et coordination disponibles 24 heures sur 24 pour garantir des services de transport rapides et dignes.',
        'HUMAN_REMAINS_FEATURE_5_TITLE': 'Conformité Réglementaire :',
        'HUMAN_REMAINS_FEATURE_5_DESC': 'Conformité totale avec les réglementations de l\'IATA, les exigences sanitaires internationales et les réglementations d\'importation/exportation du pays de destination.',
        'SERVICES_INCLUDED_TITLE': 'Nos Services Incluent :',
        'SERVICE_1_TITLE': 'Rapatriement International :',
        'SERVICE_1_DESC': 'Transport international complet de dépouilles mortelles avec toute la documentation nécessaire et le dédouanement.',
        'SERVICE_2_TITLE': 'Transport National :',
        'SERVICE_2_DESC': 'Transport national fiable de dépouilles mortelles à travers l\'Inde avec une manipulation et une documentation appropriées.',
        'SERVICE_3_TITLE': 'Aide à la Documentation :',
        'SERVICE_3_DESC': 'Assistance complète pour tous les documents requis, y compris les certificats de décès, les certificats d\'embaumement et les permis de transport.',
        'SERVICE_4_TITLE': 'Dédouanement :',
        'SERVICE_4_DESC': 'Services experts de dédouanement pour le transport international de dépouilles mortelles en pleine conformité réglementaire.',
        'SERVICE_5_TITLE': 'Coordination avec les Compagnies Aériennes :',
        'SERVICE_5_DESC': 'Coordination directe avec les compagnies aériennes pour assurer une manipulation appropriée et un transport rapide des dépouilles mortelles.'
    },

    de: {
        // Navigation
        'ABOUT US': 'ÜBER UNS',
        'OUR SERVICES': 'UNSERE DIENSTLEISTUNGEN',
        'MORE': 'MEHR',
        'SPECIALIZED SERVICES': 'SPEZIALISIERTE DIENSTLEISTUNGEN',
        'Healthcare Logistics': 'Gesundheitslogistik',
        'DG Shipments': 'DG-Sendungen',
        'Project Logistics': 'Projektlogistik',
        'Our Team': 'Unser Team',
        'Calculator': 'Rechner',
        'Customer Reviews': 'Kundenbewertungen',
        'CONTACT US': 'KONTAKT',
        'Have any Questions?': 'Haben Sie Fragen?',
        'COMPANY_MAIN': 'EASTERN CARGO',
        'COMPANY_SUB': 'CARRIERS (I) PVT.LTD',
        'EMAIL_INFO': 'info@easterncargo.co.in',
        'EMAIL_LSETH': 'lseth@easterncargo.co.in',
        'PHONE_NO': '+91-22-67539999',
        'LANGUAGE_SELECTOR_TEXT': 'DE',

        // Hero Section
        'Worldwide Logistics': 'Weltweite Logistik',
        'International Air Freight': 'Internationaler Luftfracht',
        'Contact Us': 'Kontaktieren Sie uns',
        'Get your free quote today': 'Erhalten Sie heute Ihr kostenloses Angebot',
        'Reliable & Efficient': 'Zuverlässig und Effizient',
        'Multimodal Transport Network': 'Multimodales Transportnetzwerk',
        'Our Services': 'Unsere Dienstleistungen',
        'Global Trade Solutions': 'Globale Handelslösungen',
        'Ocean Freight Solutions': 'Seefrachtlösungen',
        'Get a Quote': 'Angebot erhalten',
        'Select Service': 'Dienstleistung auswählen',
        'Air Freight': 'Luftfracht',
        'Sea Freight': 'Seefracht',
        'Land Transport': 'Landtransport',
        'Warehousing': 'Lagerung',
        'Pharma Logistics': 'Pharma-Logistik',
        'DGR Shipments': 'DGR-Sendungen',
        'Project Logistics': 'Projektlogistik',
        'Name': 'Name',
        'Email': 'E-Mail',
        'Phone': 'Telefon',
        'Service Type': 'Dienstleistungstyp',
        'Your Message': 'Ihre Nachricht',
        'Enter CAPTCHA': 'CAPTCHA eingeben',
        'Request A Quote': 'Angebot anfordern',
        'WRONG_CAPTCHA': '❌ Falsches CAPTCHA',
        'CORRECT_CAPTCHA': '✅ CAPTCHA verifiziert',

        //WHY CHOOSE US
        'WHY CHOOSE US': 'WARUM UNS WÄHLEN',
        'Delivering Comprehensive Global Logistics Solutions': 'Umfassende globale Logistiklösungen liefern.',
        'WHAT WE DO': 'WAS WIR TUN',
        'OUR AWARD': 'UNSER PREIS',
        'COMPANY HISTORY': 'UNTERNEHMENSGESCHICHTE',
        'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Eastern Cargo ist ein unabhängiges, in Privatbesitz befindliches indisches Unternehmen mit über 45 Jahren Erfahrung in der Bereitstellung von End-to-End-Import- und Exportdienstleistungen, die Luft-, See- und Landtransport sowie eine fachkundige Zollabfertigung umfassen. Wir liefern Lösungen in mehreren Branchen wie Projekten, Chemikalien, Pharma, Bekleidung, technischen Gütern, Flüssigfracht, Gefahrgut, temperaturkontrollierter Logistik und E-Commerce, die alle durch eine starke Pan-Indien-Präsenz unterstützt werden.',
        'Warehouse Facility': 'Lagereinrichtung',
        'Air Freight Facility': 'Luftfracht-Einrichtung',
        'Cost Effective Pricing': 'Kostengünstige Preise',
        'Timely Delivery': 'Pünktliche Lieferung',
        'Container delivery': 'Containerlieferung',
        'Best Team Member': 'Bestes Teammitglied',
        'Learn More': 'Mehr erfahren',
        'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': 'Unser Unternehmen ist darauf spezialisiert, maßgeschneiderte Luft- und Seetransportlösungen anzubieten, um den einzigartigen Bedürfnissen jedes Kunden gerecht zu werden. Ob es sich um internationale Spedition oder zeitkritische Fracht handelt, wir gewährleisten zuverlässige, effiziente und kostengünstige Dienstleistungen in globalen Lieferketten. Wir liefern Lösungen in mehreren Branchen wie Projekten, Chemikalien, Pharma, Bekleidung, technischen Gütern, Flüssigfracht, Gefahrgut, temperaturkontrollierter Logistik und E-Commerce, die alle durch eine starke Pan-Indien-Präsenz unterstützt werden.',
        'Global Network': 'Globales Netzwerk',
        'Real-time Tracking': 'Echtzeit-Verfolgung',
        'Customs Expertise': 'Zollexpertise',
        'Multi-modal Transport': 'Multimodaler Transport',
        'Risk Management': 'Risikomanagement',
        'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.': 'Eastern Cargo hat zahlreiche renommierte Branchenpreise für herausragende Leistungen in der Spedition und Logistik erhalten. Unsere konstante Leistung und unser Engagement für Qualität haben uns die Anerkennung führender Fluggesellschaften, globaler Spediteure und vertrauenswürdiger Logistikagenten eingebracht und unseren Ruf als zuverlässiger Partner für internationale Frachtlösungen gefestigt.',
        'ISO Certified': 'ISO-zertifiziert',
        'Industry Awards': 'Branchenpreise',
        'Quality Standards': 'Qualitätsstandards',
        'Customer Recognition': 'Kundenanerkennung',
        'AEO certified': 'AEO-zertifiziert',
        'Excellence Certificates': 'Exzellenzzertifikate',

        // Memberships
        'Memberships & Certifications': 'Mitgliedschaften und Zertifizierungen',
        'Proud members of leading global logistics organizations': 'Stolze Mitglieder führender globaler Logistikorganisationen',
        'ISO 9001:2015': 'ISO 9001:2015',
        'AEO Certified': 'AEO-zertifiziert',
        'WCA Member': 'WCA-Mitglied',
        'IATA Agent': 'IATA-Agent',
        'FIATA Member': 'FIATA-Mitglied',
        'ACAAI Member': 'ACAAI-Mitglied',
        'MIFFA Member': 'MIFFA-Mitglied',

        // About Section
        'About EASTERN CARGO CARRIERS (I) PVT.LTD': 'Über EASTERN CARGO CARRIERS (I) PVT.LTD',
        'Our Legacy & Commitment': 'Unser Erbe und Engagement',
        'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.': 'Als stolz unabhängiges und privat geführtes indisches Unternehmen bringt Eastern Cargo Carriers (I) Pvt. Ltd. über 45 Jahre engagierte Erfahrung in die Logistikbranche ein. Wir sind darauf spezialisiert, umfassende "End-to-End"-Dienstleistungen für unsere Kunden zu erbringen, die alle Aspekte von Importen und Exporten über Luft-, See- und Landtransport abdecken, komplett mit nahtloser Zollabfertigung.',
        'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.': 'Unsere globale Präsenz wird durch unsere offizielle Registrierung als Multimodal Transport Operator (MTO) bei der DG Shipping, Regierung von Indien, gestärkt. Dies ermöglicht es uns, spezialisierte Expertise in einer breiten Palette von Bereichen anzubieten, einschließlich Projektfracht, Chemikalien, Pharmazeutika, Bekleidung, Ingenieurwaren, Flüssigfracht, Gefahrgut (Haz), temperaturkontrollierte Sendungen und E-Commerce-Logistik.',
        'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.': 'Wir verpflichten uns zu den höchsten Qualitätsstandards, demonstriert durch unsere ISO 9001-Zertifizierung, AEO-Zertifizierung für optimierte Zollabfertigung und unser GDP-konformes Lager. Als registrierte Mitglieder von IATA und FIATA halten wir uns an globale Best Practices.',
        'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.': 'Mit einer robusten Pan-Indien-Präsenz bieten wir flexible und leistungsstarke Lösungen, von der Handhabung temperaturkontrollierter, gefährlicher und flüssiger Fracht bis hin zur Organisation vollständiger oder teilweiser Luft- und Seecharter. Unsere Seefrachtkapazitäten decken alles ab, von FCL- und LCL-Containern bis hin zu Schüttgut, RORO, Schwertransporten, Spezialausrüstung und anderen abnormalen Frachten.',

        // Timeline
        'Ecc\'s Group Key Milestones in Aviation and Logistics': 'Wichtige Meilensteine der Ecc-Gruppe in Luftfahrt und Logistik',
        'YEAR_1979': '1979',
        'Custom House Agent': 'Zollagent',
        'Established as a CHA': 'Als CHA etabliert',
        'CHA_TITLE': 'Zollagent (CHA)',
        'CHA_DESC': 'Eastern Cargo Carriers begann seine Reise als Zollagent und bot wesentliche Zolldienstleistungen für Import- und Exportvorgänge an. Dies bildete die Grundlage für unsere Logistikexpertise.',
        'CHA_LIST_1': 'Zolldienstleistungen',
        'CHA_LIST_2': 'Bearbeitung von Dokumentationen',
        'CHA_LIST_3': 'Import-/Export-Erleichterung',
        'YEAR_1984': '1984',
        'IATA Agent': 'IATA-Agent',
        'Leveraging accreditation': 'Akkreditierung nutzen',
        'IATA_TITLE': 'IATA-Akkreditierung',
        'IATA_DESC': 'Erwarb die Akkreditierung der International Air Transport Association (IATA), die es uns ermöglicht, umfassende Luftfrachtdienste mit globaler Reichweite und branchenüblichen Praktiken anzubieten.',
        'IATA_LIST_1': 'Globales Luftfrachtnetzwerk',
        'IATA_LIST_2': 'Einhaltung der IATA-Standards',
        'IATA_LIST_3': 'Internationale Frachtoperationen',
        'YEAR_1989': '1989',
        'Charter Operation': 'Charter-Betrieb',
        'Initiated first charter': 'Ersten Charter initiiert',
        'CHARTER_TITLE': 'Start der Charter-Operationen',
        'CHARTER_DESC': 'Startete unsere Charter-Operations-Abteilung, um spezielle Flugzeuglösungen für dringende und spezialisierte Frachtanforderungen bereitzustellen. Dies erweiterte unser Serviceportfolio erheblich.',
        'CHARTER_LIST_1': 'Spezielle Flugzeug-Charter',
        'CHARTER_LIST_2': 'Lösungen für dringende Fracht',
        'CHARTER_LIST_3': 'Spezialisierte Transportdienste',
        'YEAR_1994': '1994-99',
        'Network Expansion': 'Netzwerkausbau',
        'Achieved Pan-India presence': 'Pan-Indien-Präsenz erreicht',
        'NETWORK_TITLE': 'Pan-Indien-Netzwerkausbau',
        'NETWORK_DESC': 'Erfolgreich unsere Operationen in ganz Indien erweitert, um ein umfassendes Netzwerk von Büros und Servicezentren für landesweite Logistiklösungen aufzubauen.',
        'NETWORK_LIST_1': 'Landesweite Präsenz',
        'NETWORK_LIST_2': 'Mehrere Bürostandorte',
        'NETWORK_LIST_3': 'Umfassendes Servicenetzwerk',
        'YEAR_2005': '2005-11',
        'GSAs & Consolidation': 'GSAs & Konsolidierung',
        'Key GSA partnerships': 'Wichtige GSA-Partnerschaften',
        'GSA_TITLE': 'GSA-Partnerschaften & Konsolidierung',
        'GSA_DESC': 'Formierte strategische Partnerschaften als General Sales Agent (GSA) mit führenden internationalen Fluggesellschaften und Reedereien, um unsere Position als führender Logistikanbieter zu festigen.',
        'GSA_LIST_1': 'Strategische Airline-Partnerschaften',
        'GSA_LIST_2': 'Globale Versandallianzen',
        'GSA_LIST_3': 'Verbesserte Servicefähigkeiten',
        'YEAR_2015': '2015-16',
        'Pharma Expertise': 'Pharma-Expertise',
        'Specialized services': 'Spezialisierte Dienstleistungen',
        'PHARMA_TITLE': 'Logistikexpertise für Pharmazeutika',
        'PHARMA_DESC': 'Entwickelte spezialisierte Expertise in der Pharma-Logistik, einschließlich temperaturkontrolliertem Transport und GDP-konformer Lagerung für Biowissenschaftsprodukte.',
        'PHARMA_LIST_1': 'Temperaturkontrollierte Lösungen',
        'PHARMA_LIST_2': 'GDP-konforme Lagerung',
        'PHARMA_LIST_3': 'Pharma-spezifische Expertise',
        'YEAR_2017': '2017-18',
        'Temp Warehouse': 'Temp-Lager',
        'Pharma packaging': 'Pharma-Verpackung',
        'TEMP_WAREHOUSE_TITLE': 'Temperaturkontrolliertes Lager',
        'TEMP_WAREHOUSE_DESC': 'Etablierte dedizierte temperaturkontrollierte Lagereinrichtungen für pharmazeutische Produkte, um eine ordnungsgemäße Lagerung und Handhabung empfindlicher Fracht zu gewährleisten.',
        'TEMP_WAREHOUSE_LIST_1': 'Temperaturkontrollierte Lagerung',
        'TEMP_WAREHOUSE_LIST_2': 'Pharma-Verpackungsdienste',
        'TEMP_WAREHOUSE_LIST_3': 'Qualitätssicherungsprotokolle',
        'YEAR_2019': '2019-20',
        'Critical Response': 'Kritische Reaktion',
        'Imported life-saving drugs': 'Importierte lebensrettende Medikamente',
        'CRITICAL_RESPONSE_TITLE': 'Kritische Reaktionsoperationen',
        'CRITICAL_RESPONSE_DESC': 'Bewältigte erfolgreich kritische Reaktionsoperationen während der Pandemie, indem lebensrettende Medikamente und medizinische Hilfsgüter mit beispielloser Geschwindigkeit und Effizienz importiert wurden.',
        'CRITICAL_RESPONSE_LIST_1': 'Medizinische Notfallversorgung',
        'CRITICAL_RESPONSE_LIST_2': 'Schnelle Reaktionslogistik',
        'CRITICAL_RESPONSE_LIST_3': 'Transport von lebensrettenden Medikamenten',
        'YEAR_2020': '2020-21',
        'Governor\'s Award': 'Gouverneurs-Preis',
        'For Pharma Exports': 'Für Pharma-Exporte',
        'GOVERNOR_AWARD_TITLE': 'Anerkennung durch den Gouverneurs-Preis',
        'GOVERNOR_AWARD_DESC': 'Erhielt den prestigeträchtigen Gouverneurs-Preis für Exzellenz bei Pharma-Exporten, als Anerkennung für unseren herausragenden Beitrag zur Gesundheitslogistik.',
        'GOVERNOR_AWARD_LIST_1': 'Exzellenz bei Pharma-Exporten',
        'GOVERNOR_AWARD_LIST_2': 'Branchenanerkennung',
        'GOVERNOR_AWARD_LIST_3': 'Führerschaft in der Gesundheitslogistik',

        // Services
        'Wide variety of logistics services': 'Breite Palette an Logistikdienstleistungen',
        'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.': 'Unser Logistikunternehmen bietet eine vielfältige Palette von Dienstleistungen, die auf die einzigartigen Bedürfnisse jedes Kunden zugeschnitten sind. Von Lagerung und Distribution bis hin zu Transportmanagement und Versorgung.',
        'Air Freight (Export & Import)': 'Luftfracht (Export & Import)',
        'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.': 'Mit über 40 Jahren auf dem Markt haben wir eine starke Reichweite mit einer breiten Palette von Fluggesellschaften, um aggressive Preise und maßgeschneiderte Lösungen anzubieten.',
        'Ocean Freight (Import & Export)': 'Seefracht (Import & Import)',
        'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.': 'Umfassende Seefrachtdienste für alle Ihre Import- und Exportbedürfnisse, die eine zuverlässige und pünktliche Lieferung weltweit gewährleisten.',
        'Customs Brokerage': 'Zollabfertigung',
        'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.': 'Wir bieten eine Reihe von wertschöpfenden Zolldienstleistungen an, um Ihre Sendungen schnell und effizient durch den Zoll zu bringen.',
        'Warehouse & Distribution': 'Lagerung & Distribution',
        'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.': 'Um sicherzustellen, dass Ihre Lieferkette reibungslos läuft, bieten wir dedizierte und geteilte Lager- und Distributionsdienstleistungen an.',
        'Air Charter': 'Luftcharter',
        'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.': 'Seit 1989 bieten wir dringende und umfassende Luftfracht-Charterdienste an und bearbeiten Anfragen mit gründlicher Schulung.',
        'Your Pet Pal': 'Ihr Haustier-Kumpel',
        'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.': 'Von Katzen und Hunden bis hin zu Pferden haben wir das Wissen, Ihre Haustiere sanft und sorgfältig zu ihrem Ziel zu transportieren.',
        'Express Logistics': 'Express-Logistik',
        'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.': 'Unsere internationalen Express-Frachtdienste gewährleisten eine schnelle und zuverlässige Lieferung für Ihre dringenden globalen Sendungen.',
        'Unaccompanied Baggage Shipping': 'Versand von unbegleitetem Gepäck',
        'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.': 'Der Versand von persönlichem Gepäck nimmt den Stress aus Ihrem Umzug, indem überschüssige Gegenstände mit fachkundiger Sorgfalt behandelt werden. Wir kümmern uns um professionelle Verpackung und Zollabfertigung.',

        // Customer Reviews
        'What our clients say': 'Was unsere Kunden sagen',
        'Trusted experiences shared by our customers': 'Vertrauenswürdige Erfahrungen, die unsere Kunden teilen.',
        'TESTIMONIAL_1_TITLE': 'Superschnelle Lieferung',
        'TESTIMONIAL_1_DESC': 'Eastern Cargo Carriers bot einen exzellenten Service für meine Sendung. Von der Abholung bis zur Lieferung war alles nahtlos und pünktlich. Ich schätze ihren Professionalismus und ihren Kundensupport wirklich sehr.',
        'TESTIMONIAL_2_TITLE': 'Exzellente Dienstleistungen',
        'TESTIMONIAL_2_DESC': 'Sehr professionelles Unternehmen mit zuverlässigen Diensten und ohne Verzögerungen. Jede Sendung wird reibungslos und pünktlich abgewickelt, was mir vollständige Sorgenfreiheit gibt. Wirklich eine der besten Entscheidungen für verlässliche Frachtlösungen.',
        'TESTIMONIAL_3_TITLE': 'Zuverlässiger Partner',
        'TESTIMONIAL_3_DESC': 'Eastern Cargo Carriers ist zu unserem bevorzugten Partner geworden. Ihre Pünktlichkeit, Professionalität und Zuverlässigkeit stellen sicher, dass jede Lieferung mit Sorgfalt und immer pünktlich abgewickelt wird.',
        'TESTIMONIAL_4_TITLE': 'Erschwinglich & Sicher',
        'TESTIMONIAL_4_DESC': 'Eastern Cargo Carriers bietet die wirtschaftlichste und sicherste Art, Sendungen aus den VAE zu versenden. Ihre Pünktlichkeit, Professionalität und Zuverlässigkeit machen den gesamten Prozess reibungslos und stressfrei.',
        'TESTIMONIAL_5_TITLE': 'Hervorragender Support',
        'TESTIMONIAL_5_DESC': 'Eastern Cargo Carriers hat mich mit ihrem professionellen Support-Team beeindruckt. Sie lieferten zeitnahe Updates, behandelten jede Anfrage mit Sorgfalt und stellten sicher, dass meine Sendung pünktlich und ohne Probleme ankam.',
        'TESTIMONIAL_6_TITLE': 'Seit Jahren vertrauenswürdig',
        'TESTIMONIAL_6_DESC': 'Wir verlassen uns seit Jahren auf Eastern Cargo Carriers, und ihre Beständigkeit in Pünktlichkeit, Professionalität und zuverlässigem Service hat sie zu unserer ersten Wahl für jede Sendung gemacht.',

        // Calculator
        'Smart Cargo Calculator': 'Intelligenter Frachtrechner',
        'Centimeters (CM)': 'Zentimeter (CM)',
        'Inches (IN)': 'Zoll (IN)',
        'Package Dimensions': 'Paketabmessungen',
        '+ Add Package': '+ Paket hinzufügen',
        'Reset': 'Zurücksetzen',
        'Calculate': 'Berechnen',

        // Career/Contact Forms
        'Join Our Team': 'Werden Sie Teil unseres Teams',
        'Build your career with Eastern Cargo Carriers – explore exciting opportunities today.': 'Bauen Sie Ihre Karriere mit Eastern Cargo Carriers auf – entdecken Sie noch heute spannende Möglichkeiten.',
        'Upload Resume': 'Lebenslauf hochladen',
        'Your Message (Optional)': 'Ihre Nachricht (optional)',
        'Submit Application': 'Bewerbung absenden',
        'Request your free logistics quote today and experience hassle-free shipping.': 'Fordern Sie noch heute Ihr kostenloses Logistikangebot an und erleben Sie einen reibungslosen Versand.',

        // Footer
        'FOOTER_HEADING': 'Eastern Cargo Carriers (I) Pvt.Ltd.',
        'FOOTER_ADDRESS': 'Unit #25/26/27, Adarsh Industrial Estate, Sahar Road, Chakala, Andheri (East), Mumbai – 400 099',
        'Quick Links': 'Schnelllinks',
        'About Us': 'Über uns',
        'Careers': 'Karriere',
        'Get a Quote': 'Angebot anfordern',
        'Our Team': 'Unser Team',
        'Our Services': 'Unsere Dienstleistungen',
        'Client Reviews': 'Kundenbewertungen',
        'Specialized Services': 'Spezialisierte Dienstleistungen',
        'Express Logistics': 'Express-Logistik',
        'Healthcare Logistics': 'Gesundheitslogistik',
        'DG Shipments': 'DG-Sendungen',
        'Project Logistics': 'Projektlogistik',
        'Find Us': 'Uns finden',
        'Follow us :': 'Folgen Sie uns :',
        'COPYRIGHT': '© Copyright 2025. Alle Rechte vorbehalten von Eastern Cargo Carriers (I) Pvt.Ltd',
        'Select Language': 'Sprache auswählen',
        'CLOSE_MODAL': '×',
        'English': 'Englisch',
        'Spanish': 'Spanisch',
        'French': 'Französisch',
        'German': 'Deutsch',
        'Chinese': 'Chinesisch',
        'Japanese': 'Japanisch',

        //Menu
        'ABOUT US': 'ÜBER UNS',
        'OUR SERVICES': 'UNSERE DIENSTLEISTUNGEN',
        'MORE': 'MEHR',
        'SPECIALIZED SERVICES': 'SPEZIALISIERTE DIENSTLEISTUNGEN',
        'Healthcare Logistics': 'Gesundheitslogistik',
        'DG Shipments': 'DG-Sendungen',
        'Project Logistics': 'Projektlogistik',
        'Our Team': 'Unser Team',
        'Calculator': 'Rechner',
        'Customer Reviews': 'Kundenbewertungen',
        'CONTACT US': 'KONTAKT',
        'Have any Questions?': 'Haben Sie Fragen?',

        //Air Freight
        "Air Freight (Export & Import Services)": "Luftfracht (Export- & Importdienstleistungen)",
        "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.": "Mit über 40 Jahren Führungsposition auf dem indischen Markt zeichnet sich Eastern Cargo Carriers (I) Pvt. Ltd. durch seine weitreichende Präsenz und starke Partnerschaften mit regionalen und internationalen Fluggesellschaften aus. Wir stärken unsere Kunden zusätzlich durch ein robustes globales Agentennetzwerk, das echte Tür-zu-Tür-Luftfrachtlösungen ermöglicht – von der Abholung am Ursprungsort bis zur endgültigen Zustellung am Zielort. Diese unübertroffene Kombination ermöglicht es uns, zuverlässig schnellen Service, äußerst wettbewerbsfähige Preise und vollständige Kontrolle zu allen wichtigen Zielen weltweit anzubieten. Ob Sie Standard-Luftfracht oder spezialisierte, sensible Frachtlogistik benötigen, unsere maßgeschneiderten Lösungen stellen sicher, dass Ihre Fracht bei jedem Schritt schnell, sicher und effizient bewegt wird.",
        "Why Choose Our Air Freight Services?": "Warum Sie unsere Luftfrachtdienste wählen sollten?",
        "Aggressive, Competitive Rates:": "Aggressive, wettbewerbsfähige Preise:",
        "Leverage our airline relationships for the best pricing to key global hubs.": "Nutzen Sie unsere Beziehungen zu Fluggesellschaften für die besten Preise zu wichtigen globalen Drehkreuzen.",
        "Faster Transit Times:": "Schnellere Transitzeiten:",
        "Priority access ensures your cargo arrives on schedule—every time.": "Prioritärer Zugang stellt sicher, dass Ihre Fracht pünktlich ankommt – jedes Mal.",
        "Advanced Cold Chain & Temperature Control:": "Fortschrittliche Kühlkette & Temperaturkontrolle:",
        "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.": "Wir behandeln Kühlcontainer-, temperaturempfindliche und aktive Container- (Envirotainer) Sendungen mit Fachwissen.",
        "Specialized Cargo Handling:": "Spezialisierte Frachtabfertigung:",
        "From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.": "Von DGR (Gefahrgut) über Wertsachen, Haustiere/lebende Tiere bis hin zu menschlichen Überresten – unser Team kümmert sich um alles mit Sorgfalt und Konformität.",
        "End-to-End Service:": "End-to-End-Service:",
        "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.": "Erhalten Sie umfassende Lösungen einschließlich Abholung/Lieferung, Verpackung, Kennzeichnung, Dokumentation, Versicherung und Zollabfertigung.",
        "Additional Capabilities": "Zusätzliche Fähigkeiten",
        "Cargo consolidation for cost efficiency to key destinations.": "Frachtkonsolidierung für Kosteneffizienz zu wichtigen Zielen.",
        "Expert handling of personal effects, household goods, and chartered flight operations.": "Fachkundige Abfertigung von persönlichen Gegenständen, Haushaltswaren und Charterflugoperationen.",
        "Full spectrum of value-added services with and expert support at every step.": "Ein vollständiges Spektrum an Mehrwertdiensten mit fachkundiger Unterstützung bei jedem Schritt.",

        //OCEAN_FREIGHT
        "OCEAN_FREIGHT_TITLE": "Seefracht (Import- & Exportdienstleistungen)",
        "OCEAN_FREIGHT_DESC": "Der gute Ruf und die starken Partnerschaften, die wir im Laufe der Jahre mit großen Reedereien aufgebaut haben, ermöglichen es uns, umfassende Seefrachtlösungen zu liefern, die strenge Zeitvorgaben für Export- und Importoperationen erfüllen. Unsere Expertise erstreckt sich über das gesamte maritime Logistikspektrum, von Standard-Containerverladungen bis hin zu komplexen Projektladungen, unterstützt durch exzellente Übersee-Agenten, die eine nahtlose Tür-zu-Tür-Lieferung weltweit gewährleisten.",
        "WHY_CHOOSE_OCEAN_FREIGHT_TITLE": "Warum unsere Seefrachtdienste wählen?",
        "OCEAN_FREIGHT_FEATURE_1_TITLE": "Umfassende FCL- & LCL-Lösungen:",
        "OCEAN_FREIGHT_FEATURE_1_DESC": "Flexible Buchungsoptionen mit wettbewerbsfähigen Raten durch unsere etablierten Partnerschaften mit Reedereien für Voll- und Sammelcontainer.",
        "OCEAN_FREIGHT_FEATURE_2_TITLE": "Spezialisierte Frachtexpertise:",
        "OCEAN_FREIGHT_FEATURE_2_DESC": "Fachmännischer Umgang mit ODC (Ladung mit abweichenden Abmessungen), Projektladung, Gefahrgut und Kühlgut mit temperaturkontrollierten Lösungen.",
        "OCEAN_FREIGHT_FEATURE_3_TITLE": "End-to-End-Service-Integration:",
        "OCEAN_FREIGHT_FEATURE_3_DESC": "Komplette Logistikverwaltung einschließlich Zollabfertigung, Verpackung, Palettierung, Seeversicherung und DDU/DDP-Abwicklung.",
        "OCEAN_FREIGHT_FEATURE_4_TITLE": "Globales Netzwerk & Spezialisierung auf Handelsrouten:",
        "OCEAN_FREIGHT_FEATURE_4_DESC": "Ein ausgedehntes Netzwerk von Übersee-Agenten gewährleistet zuverlässigen Service auf spezialisierten Handelsrouten mit lokaler Expertise.",
        "OCEAN_FREIGHT_FEATURE_5_TITLE": "Maritime Mehrwertdienste:",
        "OCEAN_FREIGHT_FEATURE_5_DESC": "Umfassende Unterstützung einschließlich Konsolidierung/Dekonsolidierung, Lagerhaltung, Distribution, Transport und Abfertigung von persönlichen Effekten für ein komplettes Lieferkettenmanagement.",

        //CUSTOMS_BROKERAGE
        "CUSTOMS_BROKERAGE_TITLE": "Zollabfertigungsdienste",
        "CUSTOMS_BROKERAGE_DESC": "Die Navigation durch komplexe internationale Handelsvorschriften erfordert fachkundige Zollabfertigungsdienste, die eine schnelle, konforme Abfertigung Ihrer Exportsendungen gewährleisten. Als AEO-zertifizierte Zollagenten mit tiefgreifender regulatorischer Expertise optimieren wir den gesamten Zollprozess, minimieren Verzögerungen und optimieren die Zollkosten für Unternehmen aller Branchen.",
        "WHY_CHOOSE_CUSTOMS_BROKERAGE_TITLE": "Warum unsere Zollabfertigungsdienste wählen?",
        "CUSTOMS_BROKERAGE_FEATURE_1_TITLE": "AEO-zertifizierte Expertise:",
        "CUSTOMS_BROKERAGE_FEATURE_1_DESC": "Der Status des Zugelassenen Wirtschaftsbeteiligten gewährleistet eine schnellere, vertrauenswürdige Zollabfertigung mit reduzierten Inspektionen.",
        "CUSTOMS_BROKERAGE_FEATURE_2_TITLE": "Vollständige Einhaltung der Vorschriften:",
        "CUSTOMS_BROKERAGE_FEATURE_2_DESC": "Vollständige Dokumentenverwaltung, Zolltarifklassifizierung und Einhaltung aller Import-/Exportvorschriften.",
        "CUSTOMS_BROKERAGE_FEATURE_3_TITLE": "Zoll- & Kostenoptimierung:",
        "CUSTOMS_BROKERAGE_FEATURE_3_DESC": "Strategische Zolltarifklassifizierung und Nutzung von Handelsabkommen zur Minimierung von Zöllen und Gebühren.",
        "CUSTOMS_BROKERAGE_FEATURE_4_TITLE": "Spezialisierte Frachtabfertigung:",
        "CUSTOMS_BROKERAGE_FEATURE_4_DESC": "Fachmännische Abfertigung von Gefahrgut, beschränkten Waren und hochwertigen Sendungen unter Einhaltung der Vorschriften.",
        "CUSTOMS_BROKERAGE_FEATURE_5_TITLE": "End-to-End-Unterstützung:",
        "CUSTOMS_BROKERAGE_FEATURE_5_DESC": "Umfassender Service von der Dokumentationsvorbereitung bis zur endgültigen Lieferung.",

        //WAREHOUSE
        "WAREHOUSE_TITLE": "Lager- und Vertriebsdienstleistungen",
        "WAREHOUSE_DESC": "Bei Eastern Cargo Carriers (I) Pvt.LTD stellen wir sicher, dass Ihre Lieferkette reibungslos funktioniert, indem wir sowohl dedizierte als auch geteilte Lager- und Vertriebsdienstleistungen anbieten, die auf Ihre Bedürfnisse zugeschnitten sind. Unser erfahrenes Mitarbeiterteam bietet robuste Unterstützung in jeder Phase des Transports und verwaltet Ihre Waren effizient von der Lagerung bis zur endgültigen Lieferung. Ob Sie kurz- oder langfristige Lagerung benötigen, wir bieten sichere, organisierte Einrichtungen, die für Palettierung, Verpackung, Schrumpffolierung und Etikettierung ausgestattet sind. Unser strategisches Lagernetzwerk ermöglicht einen schnellen und zuverlässigen Zugang zu wichtigen Handelsrouten und stellt sicher, dass Ihre Produkte die Kunden pünktlich erreichen – jedes Mal. Wir kümmern uns auch um spezielle Anforderungen wie die Begasung, um die Produktsicherheitsstandards aufrechtzuerhalten und internationale Vorschriften einzuhalten.",

        //AIR_CHARTER
        "AIR_CHARTER_TITLE": "Luftfracht-Charterdienste",
        "AIR_CHARTER_DESC": "Seit 1989 hat sich Eastern Cargo Carriers auf dringende und umfassende Luftfracht-Charter für zeitkritische und spezialisierte Sendungen spezialisiert. Unser engagiertes Team ist fachmännisch geschult im Umgang mit komplexer Fracht – von lebensrettenden Pharmazeutika während der Pandemie bis hin zu übergroßer Industrieausrüstung – und stellt sicher, dass Ihre Fracht mit unübertroffener Geschwindigkeit, Sicherheit und Flexibilität geliefert wird. Wir bieten Voll- und Teilcharteroptionen, die vollständige Kontrolle über den Transportprozess bieten, mit End-to-End-Management einschließlich Flugzeugpositionierung, Abfertigung, Zollkoordination und Flughafen-zu-Flughafen-Lieferung an allen großen indischen Flughäfen.",
        "WHY_CHOOSE_AIR_CHARTER_TITLE": "Warum unsere Luftfracht-Charterdienste wählen?",
        "AIR_CHARTER_FEATURE_1_TITLE": "Individuelle Charteroptionen:",
        "AIR_CHARTER_FEATURE_1_DESC": "Voll- oder Teilcharter, Einweg- oder Hin- und Rückflug, zugeschnitten auf Ihren Zeitplan und Ihre Frachtanforderungen.",
        "AIR_CHARTER_FEATURE_2_TITLE": "Notfall-Logistik-Expertise:",
        "AIR_CHARTER_FEATURE_2_DESC": "Nachgewiesene Erfolgsbilanz bei der Durchführung kritischer Missionen – wie pandemiebedingter Pharmaexporte und -importe – unter strengen Zeitvorgaben.",
        "AIR_CHARTER_FEATURE_3_TITLE": "Umfassende Abfertigung:",
        "AIR_CHARTER_FEATURE_3_DESC": "Komplette Charterverwaltung von der Flugzeugpositionierung über die spezialisierte Verladung, Zollabfertigung und Lieferung bis hin zur Einhaltung der DGCA-Richtlinien.",
        "AIR_CHARTER_FEATURE_4_TITLE": "Strategischer Flughafenzugang:",
        "AIR_CHARTER_FEATURE_4_DESC": "Betrieb an allen großen indischen Zollflughäfen, was einen schnellen Umschlag und maximale Reichweite gewährleistet.",

        //PET_PAL
        "PET_PAL_TITLE": "Ihr Haustier-Kumpel: Lebendtiertransport",
        "PET_PAL_DESC": "Ob es sich um Ihre geliebte Katze oder Ihren Hund handelt – oder sogar um Pferde und Elefanten – Eastern Cargo Carriers stellt sicher, dass jedes Haustier mit größter Sorgfalt reist. Unsere spezialisierten Einrichtungen, klimatisierten Fahrzeuge und unser geschultes Tierhandling-Team optimieren eingehende und ausgehende Lebendtiertransporte. Wir wenden auch bewährte Verfahren an, um den Flugstress zu minimieren, damit Ihr Haustier ruhig und bequem ankommt.",
        "WHY_CHOOSE_PET_PAL_TITLE": "Warum sollten Sie sich für Ihr Haustier-Kumpel entscheiden?",
        "PET_PAL_FEATURE_1_TITLE": "Fachmännisches Tierhandling & Betreuung während des Fluges:",
        "PET_PAL_FEATURE_1_DESC": "Geschultes Personal befolgt die IATA-Vorschriften für lebende Tiere und kümmert sich um das Verladen, die Umgebungsbedingungen während des Fluges und die Koordination mit der Besatzung zum Wohl der Tiere.",
        "PET_PAL_FEATURE_2_TITLE": "DGCA-Konformität:",
        "PET_PAL_FEATURE_2_DESC": "Vollständige Gesundheitszeugnisse, Import-/Exportgenehmigungen und Quarantänefreigaben, die über die Tierquarantäne- und Zertifizierungsdienste an den großen indischen Flughäfen arrangiert werden.",
        "PET_PAL_FEATURE_3_TITLE": "IATA-konforme Behälter & Kennzeichnung:",
        "PET_PAL_FEATURE_3_DESC": "Sichere, belüftete Behälter mit ausreichender Polsterung, Drainage und „Lebende Tiere“-Kennzeichnung in Englisch und der Landessprache.",
        "PET_PAL_FEATURE_4_TITLE": "Personalisierte Pflegepläne:",
        "PET_PAL_FEATURE_4_DESC": "Maßgeschneiderte Fütterungs-, Bewegungs- und Sedierungsprotokolle reduzieren den Stress, mit 24-Stunden-Notfallkontaktdaten auf dem Luftfrachtbrief.",
        "PET_PAL_FEATURE_5_TITLE": "Globaler Service:",
        "PET_PAL_FEATURE_5_DESC": "Ein robustes Agentennetzwerk sorgt für eine sichere Abholung und Zustellung zu Hause, am Flughafen oder in einer Tierklinik und gewährleistet eine nahtlose Betreuungskontinuität.",

        //EXPRESS_CARGO
        "EXPRESS_CARGO_TITLE": "Zeitkritischer Express-Frachttransport",
        "EXPRESS_CARGO_DESC": "Express Cargo ist unser Premium-Service für den Transport zeitkritischer Sendungen mit optimaler Geschwindigkeit und Effizienz entlang der Lieferkette unter fachkundiger Überwachung. Von dringenden Dokumenten und wertvoller Fracht bis hin zu lebensrettenden Pharmazeutika, Blutproben für Tests, Flugzeugersatzteilen und AOG-Komponenten (Aircraft on Ground) bearbeiten wir vielfältige Expressfracht mit schnellen Servicefenstern. Unser multimodales Netzwerk kombiniert Luft-, Straßen- und Spezialtransport, um sicherzustellen, dass Ihre Waren ihr Ziel innerhalb von 24-72 Stunden für kritische Anforderungen erreichen.",
        "EXPRESS_CARGO_FEATURES_TITLE": "Lieferoptionen & Service-Merkmale",
        "EXPRESS_CARGO_FEATURE_1_TITLE": "Tür-zu-Tür-Express:",
        "EXPRESS_CARGO_FEATURE_1_DESC": "Kompletter Abhol- und Lieferservice vom Ursprungs- bis zum Zielort.",
        "EXPRESS_CARGO_FEATURE_2_TITLE": "Flughafen-zu-Flughafen-Express:",
        "EXPRESS_CARGO_FEATURE_2_DESC": "Schneller Terminal-zu-Terminal-Service für Luftfracht mit reduziertem Handling und beschleunigter Zollabfertigung.",

        //PERSONAL_EFFECTS
        "PERSONAL_EFFECTS_TITLE": "Transport von Persönlichen Gegenständen",
        "PERSONAL_EFFECTS_DESC": "Wir sind darauf spezialisiert, Ihre persönlichen Gegenstände sicher und erschwinglich zu transportieren. Wenn Gepäckbeschränkungen und Übergepäckgebühren der Fluggesellschaften Ihren Umzug gefährden, bietet Eastern Cargo Carriers nahtlose Lösungen für unbegleitetes Gepäck. Mithilfe unseres globalen Agentennetzwerks verwalten wir die Verpackung, den Zoll sowie die Tür-zu-Flughafen- und Tür-zu-Tür-Lieferung Ihrer Haushaltswaren, damit Sie sich auf das Einleben konzentrieren können, nicht auf die Versandlogistik.",
        "WHY_CHOOSE_PERSONAL_EFFECTS_TITLE": "Warum unseren Transport von Persönlichen Gegenständen wählen?",
        "PERSONAL_EFFECTS_FEATURE_1_TITLE": "Übergepäckmanagement:",
        "PERSONAL_EFFECTS_FEATURE_1_DESC": "Konsolidieren und versenden Sie Gegenstände, die die Freigepäckgrenzen der Fluggesellschaften überschreiten, als unbegleitetes Gepäck und vermeiden Sie so hohe Gebühren.",
        "PERSONAL_EFFECTS_FEATURE_2_TITLE": "Tür-zu-Tür-Abdeckung:",
        "PERSONAL_EFFECTS_FEATURE_2_DESC": "Sichere Abholung von zu Hause und Lieferung an jede Adresse weltweit über unser umfangreiches Agentennetzwerk.",
        "PERSONAL_EFFECTS_FEATURE_3_TITLE": "Professionelle Verpackung & Etikettierung:",
        "PERSONAL_EFFECTS_FEATURE_3_DESC": "Fachmännisches Verpacken in Kisten, Polsterung und Etikettierung schützen zerbrechliche Waren während des Transports.",
        "PERSONAL_EFFECTS_FEATURE_4_TITLE": "Zoll- & Dokumentenabwicklung:",
        "PERSONAL_EFFECTS_FEATURE_4_DESC": "Vollständige Abwicklung von Papieren und Freigaben, um Verzögerungen zu vermeiden und die Einhaltung von Vorschriften zu gewährleisten.",
        "PERSONAL_EFFECTS_FEATURE_5_TITLE": "End-to-End-Unterstützung:",
        "PERSONAL_EFFECTS_FEATURE_5_DESC": "Live-Sendungsaktualisierungen und engagierter Kundenservice vom Ursprung bis zur endgültigen Lieferung.",

        //HEALTHCARE_LOGISTICS
        "HEALTHCARE_LOGISTICS_TITLE": "Gesundheitslogistik",
        "HEALTHCARE_LOGISTICS_SUBTITLE": "Gesundheit mit Präzision und Sorgfalt liefern seit 1987",
        "HEALTHCARE_TRUST_TITLE": "Gesundheitslogistik, der Sie vertrauen können",
        "HEALTHCARE_TRUST_DESC": "Im Gesundheitswesen ist jede Sendung entscheidend. Bei Eastern Cargo verstehen wir, dass Leben von der sicheren, schnellen und präzisen Lieferung Ihrer medizinischen Produkte abhängen können. Deshalb bieten wir spezialisierte Logistiklösungen, die auf die einzigartigen Bedürfnisse der Gesundheits- und Biowissenschaftsbranche zugeschnitten sind.",
        "HEALTHCARE_FEATURE_1_TITLE": "Temperaturgeführter Transport:",
        "HEALTHCARE_FEATURE_1_DESC": "Validierte Verpackungen und Kühlkettenlösungen für gefrorene, gekühlte und raumtemperierte Sendungen.",
        "HEALTHCARE_FEATURE_2_TITLE": "Zeitkritische Lieferungen:",
        "HEALTHCARE_FEATURE_2_DESC": "Vorrangige Behandlung für dringende Sendungen, mit Optionen für Zustellung am selben Tag und mit dem nächsten Flug.",
        "HEALTHCARE_FEATURE_3_TITLE": "Einhaltung von Vorschriften:",
        "HEALTHCARE_FEATURE_3_DESC": "Unterstützung bei Handels-, Zoll- und Branchenvorschriften.",
        "HEALTHCARE_FEATURE_4_TITLE": "Umgang mit Proben & Ausrüstung:",
        "HEALTHCARE_FEATURE_4_DESC": "Von diagnostischen Proben und klinischen Studienkits bis hin zu chirurgischen Instrumenten und Pharmazeutika.",
        "WHY_CHOOSE_HEALTHCARE_TITLE": "Warum führende Unternehmen im Gesundheitswesen Eastern Cargo wählen:",
        "WHY_CHOOSE_HEALTHCARE_POINT_1": "✓ Engagierte Spezialisten für Gesundheitslogistik.",
        "WHY_CHOOSE_HEALTHCARE_POINT_2": "✓ Nationale und internationale Reichweite mit multimodalen Lösungen.",
        "WHY_CHOOSE_HEALTHCARE_POINT_3": "✓ 24/7 operativer Support und Notfallplanung.",
        "WHY_CHOOSE_HEALTHCARE_POINT_4": "✓ Sichere Protokolle für die Produktkette bei sensiblen Sendungen.",
        "HEALTHCARE_CLOSING_1": "Wenn Präzision und Zuverlässigkeit am wichtigsten sind – wählen Sie Eastern Cargo.",
        "HEALTHCARE_CLOSING_2": "Kontaktieren Sie noch heute unser Team für Gesundheitslogistik, um Ihre Bedürfnisse zu besprechen.",
        "PASSION_TITLE": "Eine Leidenschaft für zeitkritische Sendungen",
        "PASSION_DESC": "Mit einer Tradition im Umgang mit zeitkritischen Sendungen seit 1987 bringen wir unübertroffene Expertise in die pharmazeutische Logistik ein. Unser Team ist bekannt für die erfolgreiche Verwaltung hochwertiger Biowissenschaftsprodukte, einschließlich klinischer Studienschsendungen, neuer Produkteinführungen und Lieferungen in spezielle und anspruchsvolle Gebiete.",
        "PASSION_FEATURE_1_TITLE": "Pharma-fokussierte Operationen:",
        "PASSION_FEATURE_1_DESC": "Ein engagiertes Team, das speziell in den Feinheiten des Umgangs mit allen Arten von Biowissenschaftsprodukten geschult ist.",
        "PASSION_FEATURE_2_TITLE": "Qualität & Konformität:",
        "PASSION_FEATURE_2_DESC": "Ein Bekenntnis zu Qualitätsmanagement, operativer Exzellenz und überlegenen Zollfähigkeiten stellt sicher, dass Ihre Sendungen alle regulatorischen Standards erfüllen.",
        "PASSION_FEATURE_3_TITLE": "Temperaturgeführte Lösungen:",
        "PASSION_FEATURE_3_DESC": "Wir bieten sowohl aktive als auch passive Pharma-Lösungen, um die strikte Temperaturintegrität Ihrer Fracht zu gewährleisten.",
        "PASSION_FEATURE_4_TITLE": "Etablierte Beziehungen zu Transportunternehmen:",
        "PASSION_FEATURE_4_DESC": "Über 30 Jahre starke Partnerschaften mit Fluggesellschaften und Reedereien garantieren Zuverlässigkeit, Priorität und Kundenkomfort.",
        "TEMP_SOLUTIONS_TITLE": "Unsere temperaturgeführten Lösungen",
        "ENVIROTAINERS_TITLE": "Envirotainer (Aktiv)",
        "ENVIROTAINERS_DESC": "Wir bieten hochmoderne aktive Containerlösungen wie den Envirotainer RKN e1 und RAP e2, die kompressorbasierte Kühlung und elektrische Heizung verwenden, um präzise Produkttemperaturen zwischen +2°C und +8°C oder +15°C und +25°C unabhängig von den Umgebungsbedingungen aufrechtzuerhalten.",
        "THERMAL_BLANKETS_TITLE": "Thermodecken (Passiv)",
        "THERMAL_BLANKETS_DESC": "Um Temperaturspitzen durch direkte Sonneneinstrahlung oder Umgebungsbedingungen zu vermeiden, umhüllen wir alle temperaturempfindlichen Paletten mit hochwertigen Thermodecken. Dies hält den erforderlichen Temperaturbereich während des Transports aufrecht und stellt sicher, dass die Medikamente wirksam und sicher in der Anwendung bleiben.",
        "COOL_BOXES_TITLE": "Kühlboxen (Passiv)",
        "COOL_BOXES_DESC": "Für Produkte, die eine strengere Temperaturkontrolle erfordern, verwenden wir spezielle Kühlboxen. Diese sind ein wichtiger Bestandteil der pharmazeutischen Verpackung und speziell dafür konzipiert, die Temperatur empfindlicher Produkte wie Impfstoffe, Insulin und Blutprodukte während des Transports und der Lagerung zu halten.",

        //DGR
        "DGR_TITLE": "Gefahrgutsendungen",
        "DGR_SUBTITLE": "Gefahrgut-, Chemie- & Gefahrstofftransporte – Fachkundige Logistiklösungen",
        "DGR_DESC": "Der Transport von Gefahrgut (DG), Chemikalien und gefährlichen Materialien ist ein spezialisierter Bereich, der höchste Präzision, Fachwissen und strikte Einhaltung internationaler Sicherheitsstandards erfordert. Bei Eastern Cargo bieten wir umfassende DG-Logistiklösungen, damit Ihre Sendungen sicher auf dem Luft-, See- und Landweg transportiert werden.",
        "DGR_SERVICES_TITLE": "Unsere Logistikdienstleistungen für Gefahrgut, Chemikalien und Gefahrstoffe",
        "DGR_FEATURE_1_TITLE": "Klassifizierung & Identifizierung:",
        "DGR_FEATURE_1_DESC": "Genaue Klassifizierung von Chemikalien und Gefahrgut gemäß IATA- und lokalen Vorschriften. Wir weisen jeder Sendung die korrekten UN-Nummern, Gefahrgutklassen und Verpackungsgruppen zu.",
        "DGR_FEATURE_2_TITLE": "Zertifizierte Verpackung & Kennzeichnung:",
        "DGR_FEATURE_2_DESC": "Alle Artikel werden von geschultem Personal mit DG-konformen Materialien verpackt, markiert und gekennzeichnet, um Lecks, Verschüttungen und Unfälle zu vermeiden. Die Einhaltung internationaler Standards hat bei jeder Transportart für uns Priorität.",
        "DGR_FEATURE_3_TITLE": "Regulatorische Dokumentation & Konformität:",
        "DGR_FEATURE_3_DESC": "Wir verwalten die vollständige Dokumentation – DG-Erklärungen, Sicherheitsdatenblätter (SDB/MSDS), Genehmigungen und Versicherungen – und gewährleisten eine einwandfreie Einhaltung der Vorschriften gemäß IATA.",
        "DGR_FEATURE_4_TITLE": "Geschultes Handling & Sicherer Transport:",
        "DGR_FEATURE_4_DESC": "Ihre Gefahrgutfracht wird von zertifizierten Fachleuten unter Verwendung von DG-zugelassenen Behältern verwaltet.",
        "DGR_FEATURE_5_TITLE": "End-to-End DG-Logistikunterstützung:",
        "DGR_FEATURE_5_DESC": "Ein breites Spektrum an Dienstleistungen von der Risikobewertung und regulatorischen Beratung bis zur Versandplanung, Lieferung und sicheren Lagerung.",
        "DGR_CTA_1": "Sind Sie bereit, Ihre Gefahrgüter, Chemikalien oder gefährlichen Materialien zu versenden?",
        "DGR_CTA_2": "Kontaktieren Sie noch heute unser zertifiziertes DG-Logistikteam für ein individuelles Angebot und fachkundige Beratung zur globalen Einhaltung von DG-Versandvorschriften.",
        "DGR_QUOTE_TITLE": "Holen Sie sich Ihr kostenloses Angebot für den Gefahrgutversand",
        "DGR_QUOTE_SUBTITLE": "Kontaktieren Sie noch heute unsere DG-Experten für:",
        "DGR_QUOTE_POINT_1": "Kostenlose Beratung zu den Anforderungen für den Gefahrgutversand",
        "DGR_QUOTE_POINT_2": "Unterstützung bei der Dokumentation für DG-Exporte aus Indien.",
        "DGR_QUOTE_POINT_3": "Wettbewerbsfähige Preise für Gefahrgutdienste in Indien.",
        "DGR_QUOTE_POINT_4": "24/7-Support für Ihre Gefahrgutlogistikanforderungen.",

        //PROJECT_LOGISTICS
        "PROJECT_LOGISTICS_TITLE": "Projektlogistik",
        "PROJECT_LOGISTICS_SUBTITLE": "Spezialisierte Lösungen für komplexe Projektfracht und Schwertransporte",
        "PROJECT_CARGO_SOLUTIONS_TITLE": "End-to-End-Projektfrachtlösungen",
        "PROJECT_CARGO_SOLUTIONS_DESC": "Unsere Abteilung für Projektlogistik ist auf die Abwicklung komplexer, übergroßer und schwerer Ausrüstungstransporte für Industrieprojekte, Kraftwerke, Öl- und Gasanlagen sowie Infrastrukturentwicklung spezialisiert. Mit jahrzehntelanger Erfahrung gewährleisten wir eine nahtlose Koordination von der Fabrik bis zum Endziel.",
        "OUR_PROJECT_LOGISTICS_SERVICES_TITLE": "Unsere Projektlogistikdienstleistungen",
        "PROJECT_SERVICE_1_TITLE": "Transport von schwerem Gerät:",
        "PROJECT_SERVICE_1_DESC": "Spezialisierte Handhabung von Maschinen, Turbinen, Generatoren und Industrieausrüstung mit maßgeschneiderter Verpackung und sicherem Transport.",
        "PROJECT_SERVICE_2_TITLE": "Lösungen für übergroße Fracht:",
        "PROJECT_SERVICE_2_DESC": "Fachmännisches Management von übergroßen Sendungen, die spezielle Genehmigungen, Streckenvermessungen und spezialisierte Transportausrüstung erfordern.",
        "PROJECT_SERVICE_3_TITLE": "Projektkoordination:",
        "PROJECT_SERVICE_3_DESC": "Umfassendes Projektmanagement einschließlich Dokumentation, Zollabfertigung, Versicherung und Echtzeit-Tracking.",
        "PROJECT_SERVICE_4_TITLE": "Multimodaler Transport:",
        "PROJECT_SERVICE_4_DESC": "Nahtlose Integration von Luft-, See- und Landtransportmodi für komplexe Projektanforderungen.",
        "PROJECT_SERVICE_5_TITLE": "Lieferung & Montage vor Ort:",
        "PROJECT_SERVICE_5_DESC": "Koordination der Lieferung vor Ort, Positionierung der Ausrüstung und Installationsunterstützungsdienste.",
        "INDUSTRIES_WE_SERVE_TITLE": "Branchen, die wir bedienen",
        "INDUSTRY_1_TITLE": "Öl & Gas",
        "INDUSTRY_1_DESC": "Pipeline-Ausrüstung, Bohrmaschinen und Raffineriekomponenten",
        "INDUSTRY_2_TITLE": "Energieerzeugung",
        "INDUSTRY_2_DESC": "Turbinen, Generatoren, Transformatoren und Kraftwerksausrüstung",
        "INDUSTRY_3_TITLE": "Fertigung",
        "INDUSTRY_3_DESC": "Produktionslinien, Industriemaschinen und Fertigungsausrüstung",
        "INDUSTRY_4_TITLE": "Infrastruktur",
        "INDUSTRY_4_DESC": "Baumaschinen, Brückenkomponenten und Infrastrukturmaterialien.",

        //Human Remains
        'HUMAN_REMAINS_TITLE': 'Überführung von sterblichen Überresten',
        'HUMAN_REMAINS_DESC': 'Eastern Cargo Carriers bietet professionelle und einfühlsame Dienstleistungen zur Überführung von sterblichen Überresten mit größter Würde und Respekt. Unser erfahrenes Team versteht die sensible Natur dieser Dienstleistungen und stellt sicher, dass jeder Aspekt des Transportprozesses mit Sorgfalt, Professionalität und absoluter Vertraulichkeit behandelt wird. Wir bieten umfassende Lösungen für die nationale und internationale Überführung von sterblichen Überresten, einschließlich aller erforderlichen Dokumente, Zollabfertigung und Einhaltung gesetzlicher Vorschriften.',
        'WHY_CHOOSE_HUMAN_REMAINS_TITLE': 'Warum Sie unsere Dienstleistungen zur Überführung von sterblichen Überresten wählen sollten?',
        'HUMAN_REMAINS_FEATURE_1_TITLE': 'Einfühlsamer Service:',
        'HUMAN_REMAINS_FEATURE_1_DESC': 'Unser Team bietet einen sensiblen, respektvollen Umgang mit vollem Verständnis für die emotionale Natur dieser Dienstleistungen.',
        'HUMAN_REMAINS_FEATURE_2_TITLE': 'Vollständige Dokumentation:',
        'HUMAN_REMAINS_FEATURE_2_DESC': 'Wir kümmern uns um alle notwendigen Formalitäten, einschließlich Sterbeurkunden, Einbalsamierungszertifikate, Überführungsgenehmigungen und Zollunterlagen.',
        'HUMAN_REMAINS_FEATURE_3_TITLE': 'Internationale Expertise:',
        'HUMAN_REMAINS_FEATURE_3_DESC': 'Spezialisiertes Wissen über internationale Vorschriften, Anforderungen von Fluggesellschaften und Protokolle des Ziellandes für die Überführung von sterblichen Überresten.',
        'HUMAN_REMAINS_FEATURE_4_TITLE': '24/7-Support:',
        'HUMAN_REMAINS_FEATURE_4_DESC': 'Rund-um-die-Uhr-Hilfe und Koordination, um eine pünktliche und würdige Überführung zu gewährleisten.',
        'HUMAN_REMAINS_FEATURE_5_TITLE': 'Einhaltung von Vorschriften:',
        'HUMAN_REMAINS_FEATURE_5_DESC': 'Vollständige Einhaltung der IATA-Vorschriften, internationaler Gesundheitsanforderungen und der Import-/Exportbestimmungen des Ziellandes.',
        'SERVICES_INCLUDED_TITLE': 'Unsere Dienstleistungen umfassen:',
        'SERVICE_1_TITLE': 'Internationale Rückführung:',
        'SERVICE_1_DESC': 'Komplette internationale Überführung von sterblichen Überresten mit allen notwendigen Dokumenten und Zollabfertigung.',
        'SERVICE_2_TITLE': 'Inlandstransport:',
        'SERVICE_2_DESC': 'Zuverlässiger Inlandstransport von sterblichen Überresten in ganz Indien mit ordnungsgemäßer Handhabung und Dokumentation.',
        'SERVICE_3_TITLE': 'Hilfe bei der Dokumentation:',
        'SERVICE_3_DESC': 'Umfassende Unterstützung bei allen erforderlichen Dokumenten, einschließlich Sterbeurkunden, Einbalsamierungszertifikaten und Überführungsgenehmigungen.',
        'SERVICE_4_TITLE': 'Zollabfertigung:',
        'SERVICE_4_DESC': 'Fachkundige Zollabfertigungsdienste für die internationale Überführung von sterblichen Überresten unter vollständiger Einhaltung der Vorschriften.',
        'SERVICE_5_TITLE': 'Koordination mit Fluggesellschaften:',
        'SERVICE_5_DESC': 'Direkte Koordination mit Fluggesellschaften, um eine ordnungsgemäße Handhabung und einen pünktlichen Transport der sterblichen Überreste zu gewährleisten.'
    },

    zh: {
        // Navigation
        'ABOUT US': '关于我们',
        'OUR SERVICES': '我们的服务',
        'MORE': '更多',
        'SPECIALIZED SERVICES': '专业服务',
        'Healthcare Logistics': '医疗物流',
        'DG Shipments': '危险品运输',
        'Project Logistics': '项目物流',
        'Our Team': '我们的团队',
        'Calculator': '计算器',
        'Customer Reviews': '客户评价',
        'CONTACT US': '联系我们',
        'Have any Questions?': '有任何问题吗？',
        'COMPANY_MAIN': 'EASTERN CARGO',
        'COMPANY_SUB': 'CARRIERS (I) PVT.LTD',
        'EMAIL_INFO': 'info@easterncargo.co.in',
        'EMAIL_LSETH': 'lseth@easterncargo.co.in',
        'PHONE_NO': '+91-22-67539999',
        'LANGUAGE_SELECTOR_TEXT': 'ZH',

        // Hero Section
        'Worldwide Logistics': '全球物流',
        'International Air Freight': '国际空运',
        'Contact Us': '联系我们',
        'Get your free quote today': '立即获取免费报价',
        'Reliable & Efficient': '可靠高效',
        'Multimodal Transport Network': '多式联运网络',
        'Our Services': '我们的服务',
        'Global Trade Solutions': '全球贸易解决方案',
        'Ocean Freight Solutions': '海运解决方案',
        'Get a Quote': '获取报价',
        'Select Service': '选择服务',
        'Air Freight': '空运',
        'Sea Freight': '海运',
        'Land Transport': '陆运',
        'Warehousing': '仓储',
        'Pharma Logistics': '医药物流',
        'DGR Shipments': '危险品运输',
        'Project Logistics': '项目物流',
        'Name': '姓名',
        'Email': '邮箱',
        'Phone': '电话',
        'Service Type': '服务类型',
        'Your Message': '您的留言',
        'Enter CAPTCHA': '输入验证码',
        'Request A Quote': '请求报价',
        'WRONG_CAPTCHA': '❌ 验证码错误',
        'CORRECT_CAPTCHA': '✅ 验证码正确',

        //WHY CHOOSE US
        'WHY CHOOSE US': '为什么选择我们',
        'Delivering Comprehensive Global Logistics Solutions': '提供全面的全球物流解决方案。',
        'WHAT WE DO': '我们做什么',
        'OUR AWARD': '我们的奖项',
        'COMPANY HISTORY': '公司历史',
        'Eastern Cargo is an independent, privately owned Indian company with over 45 years of experience providing end-to-end import and export services—covering air, sea, and land transport, along with expert customs clearance. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': '东方货运是一家独立的私人印度公司，拥有超过45年的经验，提供端到端的进出口服务，涵盖空运、海运和陆运，并提供专业的清关服务。我们提供跨多个垂直领域的解决方案，如项目、化学品、药品、服装、工程货物、液体货物、危险货物、温控物流和电子商务，所有这些都得到了强大的泛印度覆盖的支持。',
        'Warehouse Facility': '仓库设施',
        'Air Freight Facility': '空运设施',
        'Cost Effective Pricing': '成本效益定价',
        'Timely Delivery': '准时交付',
        'Container delivery': '集装箱交付',
        'Best Team Member': '最佳团队成员',
        'Learn More': '了解更多',
        'Our company specializes in delivering tailored air and ocean transportation solutions to meet the unique needs of each client. Whether it\'s international freight forwarding or time-sensitive cargo, we ensure reliable, efficient, and cost-effective services across global supply chains. We deliver solutions across multiple verticals such as projects, chemicals, pharma, garments, engineering goods, liquid cargo, hazardous cargo, temperature-controlled logistics, and e-commerce, all supported by a strong Pan India reach.': '我们公司专门提供量身定制的空运和海运解决方案，以满足每个客户的独特需求。无论是国际货运代理还是时间敏感货物，我们都确保在全球供应链中提供可靠、高效和成本效益高的服务。我们提供跨多个垂直领域的解决方案，如项目、化学品、药品、服装、工程货物、液体货物、危险货物、温控物流和电子商务，所有这些都得到了强大的泛印度覆盖的支持。',
        'Global Network': '全球网络',
        'Real-time Tracking': '实时追踪',
        'Customs Expertise': '海关专长',
        'Multi-modal Transport': '多式联运',
        'Risk Management': '风险管理',
        'Eastern Cargo has received numerous prestigious industry awards for excellence in freight forwarding and logistics. Our consistent performance and dedication to quality have earned recognition from leading airlines, global shippers, and trusted logistics agents—solidifying our reputation as a reliable partner in international cargo solutions.': '东方货运因其在货运代理和物流方面的卓越表现而获得了多项负有盛名的行业奖项。我们始终如一的表现和对质量的奉献赢得了领先航空公司、全球托运人和值得信赖的物流代理的认可，巩固了我们作为国际货运解决方案可靠合作伙伴的声誉。',
        'ISO Certified': 'ISO认证',
        'Industry Awards': '行业奖项',
        'Quality Standards': '质量标准',
        'Customer Recognition': '客户认可',
        'AEO certified': 'AEO认证',
        'Excellence Certificates': '卓越证书',
        
        // Memberships
        'Memberships & Certifications': '会员资格和认证',
        'Proud members of leading global logistics organizations': '全球领先物流组织的骄傲成员',
        'ISO 9001:2015': 'ISO 9001:2015',
        'AEO Certified': 'AEO认证',
        'WCA Member': 'WCA会员',
        'IATA Agent': 'IATA代理',
        'FIATA Member': 'FIATA会员',
        'ACAAI Member': 'ACAAI会员',
        'MIFFA Member': 'MIFFA会员',
        
        // About Section
        'About EASTERN CARGO CARRIERS (I) PVT.LTD': '关于东方货运承运人（印度）私人有限公司',
        'Our Legacy & Commitment': '我们的传承和承诺',
        'As a proudly independent and privately-owned Indian company, Eastern Cargo Carriers (I) Pvt. Ltd. brings over 45 years of dedicated experience to the logistics industry. We specialize in providing comprehensive, "End to End" service for our clients, covering all aspects of imports and exports across air, sea, and land transport, complete with seamless customs clearance.': '作为一家自豪的独立私人印度公司，东方货运承运人（印度）私人有限公司为物流行业带来了超过45年的专注经验。我们专门为客户提供全面的"端到端"服务，涵盖空运、海运和陆运进出口的所有方面，并完成无缝清关。',
        'Our global presence is bolstered by our official registration as a Multimodal Transport Operator (MTO) with the DG Shipping, Government of India. This allows us to offer specialized expertise across a wide range of verticals, including Project Cargo, Chemicals, Pharmaceuticals, Garments, Engineering Goods, Liquid Cargo, Hazardous (Haz) Cargo, Temperature-Controlled shipments, and E-Commerce logistics.': '我们在印度政府航运总局正式注册为多式联运运营商（MTO），这加强了我们的全球影响力。这使我们能够在广泛的垂直领域提供专业专长，包括项目货物、化学品、药品、服装、工程货物、液体货物、危险货物、温控货物和电子商务物流。',
        'We are committed to the highest standards of quality, demonstrated by our ISO 9001 certification, AEO certification for streamlined customs clearance, and our GDP-compliant warehouse. As registered members of IATA and FIATA, we adhere to global best practices.': '我们致力于最高质量标准，这体现在我们的ISO 9001认证、简化清关的AEO认证以及符合GDP标准的仓库。作为IATA和FIATA的注册成员，我们遵循全球最佳实践。',
        'With a robust Pan-India presence, we provide flexible and powerful solutions, from handling temperature-controlled, hazardous, and liquid cargo to arranging full or partial air and sea charters. Our ocean freight capabilities cover everything from FCL and LCL containers to break bulk, RORO, heavy lifts, special equipment, and other abnormal cargo.': '凭借强大的全印度影响力，我们提供灵活而强大的解决方案，从处理温控、危险和液体货物到安排全部或部分空运和海运包机。我们的海运能力涵盖从FCL和LCL集装箱到散货、滚装船、重吊、特殊设备和其他异常货物的一切。',
        
        // Timeline
        'Ecc\'s Group Key Milestones in Aviation and Logistics': 'Ecc集团在航空和物流领域的关键里程碑',
        'YEAR_1979': '1979',
        'Custom House Agent': '报关代理',
        'Established as a CHA': '作为CHA成立',
        'CHA_TITLE': '报关代理 (CHA)',
        'CHA_DESC': '东方货运承运人以报关代理的身份开始了其旅程，为进出口业务提供必要的清关服务。这标志着我们物流专业知识的奠定。',
        'CHA_LIST_1': '清关服务',
        'CHA_LIST_2': '文档处理',
        'CHA_LIST_3': '进出口便利化',
        'YEAR_1984': '1984',
        'IATA Agent': 'IATA代理',
        'Leveraging accreditation': '利用认证',
        'IATA_TITLE': 'IATA认证',
        'IATA_DESC': '获得国际航空运输协会（IATA）认证，使我们能够提供具有全球覆盖和行业标准实践的全面空运服务。',
        'IATA_LIST_1': '全球空运网络',
        'IATA_LIST_2': '符合IATA标准',
        'IATA_LIST_3': '国际货运操作',
        'YEAR_1989': '1989',
        'Charter Operation': '包机运营',
        'Initiated first charter': '启动首个包机',
        'CHARTER_TITLE': '包机业务启动',
        'CHARTER_DESC': '启动了我们的包机业务部门，为紧急和特殊货物需求提供专用飞机解决方案。这极大地扩展了我们的服务组合。',
        'CHARTER_LIST_1': '专用飞机包机',
        'CHARTER_LIST_2': '紧急货物解决方案',
        'CHARTER_LIST_3': '专业运输服务',
        'YEAR_1994': '1994-99',
        'Network Expansion': '网络扩展',
        'Achieved Pan-India presence': '实现全印度覆盖',
        'NETWORK_TITLE': '泛印度网络扩展',
        'NETWORK_DESC': '成功地在印度各地扩展了我们的业务，建立了全面的办公室和服务中心网络，以提供全国性的物流解决方案。',
        'NETWORK_LIST_1': '全国性覆盖',
        'NETWORK_LIST_2': '多个办公室地点',
        'NETWORK_LIST_3': '全面的服务网络',
        'YEAR_2005': '2005-11',
        'GSAs & Consolidation': 'GSA和整合',
        'Key GSA partnerships': '关键GSA合作伙伴关系',
        'GSA_TITLE': 'GSA合作伙伴关系与整合',
        'GSA_DESC': '与主要国际航空公司和航运公司建立了战略性总销售代理（GSA）合作伙伴关系，巩固了我们作为领先物流提供商的地位。',
        'GSA_LIST_1': '战略性航空公司合作伙伴关系',
        'GSA_LIST_2': '全球航运联盟',
        'GSA_LIST_3': '增强的服务能力',
        'YEAR_2015': '2015-16',
        'Pharma Expertise': '医药专长',
        'Specialized services': '专业服务',
        'PHARMA_TITLE': '医药物流专长',
        'PHARMA_DESC': '发展了医药物流的专业专长，包括温控运输和符合GDP标准的生命科学产品仓储。',
        'PHARMA_LIST_1': '温控解决方案',
        'PHARMA_LIST_2': '符合GDP标准的仓储',
        'PHARMA_LIST_3': '医药特定专长',
        'YEAR_2017': '2017-18',
        'Temp Warehouse': '临时仓库',
        'Pharma packaging': '医药包装',
        'TEMP_WAREHOUSE_TITLE': '温控仓库',
        'TEMP_WAREHOUSE_DESC': '建立了专门的温控仓储设施，用于医药产品，确保敏感货物的妥善存储和处理。',
        'TEMP_WAREHOUSE_LIST_1': '温控存储',
        'TEMP_WAREHOUSE_LIST_2': '医药包装服务',
        'TEMP_WAREHOUSE_LIST_3': '质量保证协议',
        'YEAR_2019': '2019-20',
        'Critical Response': '紧急响应',
        'Imported life-saving drugs': '进口救命药物',
        'CRITICAL_RESPONSE_TITLE': '紧急响应操作',
        'CRITICAL_RESPONSE_DESC': '在大流行期间成功处理了紧急响应操作，以空前的速度和效率进口了救命药物和医疗用品。',
        'CRITICAL_RESPONSE_LIST_1': '紧急医疗用品',
        'CRITICAL_RESPONSE_LIST_2': '快速响应物流',
        'CRITICAL_RESPONSE_LIST_3': '救命药物运输',
        'YEAR_2020': '2020-21',
        'Governor\'s Award': '州长奖',
        'For Pharma Exports': '医药出口',
        'GOVERNOR_AWARD_TITLE': '州长奖认可',
        'GOVERNOR_AWARD_DESC': '荣获久负盛名的州长奖，以表彰我们在医药出口方面的卓越贡献，认可了我们对医疗物流领域的杰出贡献。',
        'GOVERNOR_AWARD_LIST_1': '医药出口卓越表现',
        'GOVERNOR_AWARD_LIST_2': '行业认可',
        'GOVERNOR_AWARD_LIST_3': '医疗物流领导地位',

        // Services
        'Wide variety of logistics services': '广泛的物流服务',
        'Our logistics company offers a diverse range of services tailored to meet the unique needs of each client. From warehousing and distribution to transportation management and supply.': '我们的物流公司提供多样化的服务，以满足每个客户的独特需求。从仓储和配送到运输管理和供应。',
        'Air Freight (Export & Import)': '空运（进出口）',
        'With over 40+ years in the market, we have a strong reach with a wide range of airline carriers to offer aggressive pricing and tailor-made solutions.': '在市场上超过40年，我们与广泛的航空公司有强大的联系，提供激进的定价和定制解决方案。',
        'Ocean Freight (Import & Export)': '海运（进出口）',
        'Comprehensive ocean freight services for all your import and export needs, ensuring reliable and timely delivery across the globe.': '为您的所有进出口需求提供全面的海运服务，确保全球可靠及时的交付。',
        'Customs Brokerage': '报关代理',
        'We offer a range of value-added customs services to move your shipments through customs quickly and efficiently.': '我们提供一系列增值海关服务，快速高效地通过海关运送您的货物。',
        'Warehouse & Distribution': '仓储和配送',
        'To ensure your supply chain runs smoothly, we offer dedicated and shared warehousing and distribution services.': '为确保您的供应链顺畅运行，我们提供专用和共享的仓储和配送服务。',
        'Air Charter': '包机',
        'Since 1989, we have provided urgent and comprehensive Air Cargo Chartering services, handling requests with thorough training.': '自1989年以来，我们提供紧急和全面的空运包机服务，通过全面培训处理请求。',
        'Your Pet Pal': '您的宠物伙伴',
        'From cats and dogs to horses, we have the knowledge to handle and transport your pets gently and with care to their destination.': '从猫狗到马匹，我们拥有温和且细心地处理和运输您的宠物到目的地的知识。',
        'Express Logistics': '快递物流',
        'Our international express cargo services ensure rapid and reliable delivery for your urgent global shipments.': '我们的国际快递货运服务确保为您的紧急全球运输提供快速可靠的交付。',
        'Unaccompanied Baggage Shipping': '无人陪伴行李运输',
        'Personal Baggage Shipping takes the stress out of your move by handling excess items with expert care.we manage professional packing, customs clearance.': '个人行李运输通过专业护理处理多余物品，减轻您的搬家压力。我们管理专业包装、清关。',

        // Customer Reviews
        'What our clients say': '我们的客户怎么说',
        'Trusted experiences shared by our customers': '客户分享的信任体验。',
        'Superfast Delivery': '超快送货',
        'Eastern Cargo Carriers provided an excellent service for my shipment. From pickup to delivery, everything was seamless and on time. I truly appreciate their professionalism and customer support.': '东方货运承运人为我的货物提供了出色的服务。从提货到交付，一切都非常顺利和准时。我真的很感谢他们的专业精神和客户支持。',
        'Excellent Services': '卓越服务',
        'Very professional company with reliable services and no delays. Every shipment is handled smoothly and on time, giving me complete peace of mind. Truly one of the best choices for dependable cargo solutions.': '非常专业的公司，服务可靠，没有延误。每一批货物都处理得顺利且准时，让我完全放心。对于可靠的货运解决方案来说，这确实是最好的选择之一。',
        'Reliable Partner': '可靠的合作伙伴',
        'Eastern Cargo Carriers has become our trusted partner of choice. Their punctuality, professionalism, and reliability ensure every delivery is handled with care and always on time.': '东方货运承运人已成为我们值得信赖的首选合作伙伴。他们的准时、专业和可靠性确保每一次交付都得到妥善处理并准时到达。',
        'Affordable & Safe': '经济实惠且安全',
        'Eastern Cargo Carriers offers the most economical and safest way to send shipments from the UAE. Their punctuality, professionalism, and reliability make the whole process smooth and stress-free.': '东方货运承运人提供了从阿联酋发送货物最经济、最安全的方式。他们的准时、专业和可靠性使整个过程顺利且无压力。',
        'Outstanding Support': '出色的支持',
        'Eastern Cargo Carriers impressed me with their professional support team. They provided timely updates, handled every query with care, and ensured my shipment arrived punctually and without issues.': '东方货运承运人专业的支持团队给我留下了深刻的印象。他们提供了及时的更新，细心处理每一个问题，并确保我的货物准时且没有任何问题地到达。',
        'Trusted for Years': '多年信赖',
        'We’ve relied on Eastern Cargo Carriers for years, and their consistency in punctuality, professionalism, and reliable service has made them our first choice for every shipment.': '多年来我们一直信赖东方货运',

        //Menu
        'ABOUT US': '关于我们',
        'OUR SERVICES': '我们的服务',
        'MORE': '更多',
        'SPECIALIZED SERVICES': '专业服务',
        'Healthcare Logistics': '医疗物流',
        'DG Shipments': '危险品运输',
        'Project Logistics': '项目物流',
        'Our Team': '我们的团队',
        'Calculator': '计算器',
        'Customer Reviews': '客户评价',
        'CONTACT US': '联系我们',
        'Have any Questions?': '有任何问题吗？',

        //Air Freight
        "Air Freight (Export & Import Services)": "空运（进出口服务）",
        "With over 40+ years of leadership in the Indian market, Eastern Cargo Carriers (I) Pvt. Ltd. stands out for its expansive reach and strong partnerships with both regional and international airline carriers. We further empower our clients with a robust global agents’ network, enabling true door-to-door air freight solutions—from pickup at origin to final delivery at destination. This unrivalled combination allows us to offer reliably fast service, highly competitive rates, and complete control to all major destinations worldwide. Whether you require standard air shipping or specialized, sensitive cargo logistics, our tailor-made solutions ensure your freight moves with speed, security, and efficiency—every step of the way.": "凭借在印度市场超过40年的领导地位，东方货运（印度）私人有限公司以其广泛的覆盖范围以及与区域和国际航空公司的强大合作伙伴关系而脱颖而出。我们通过强大的全球代理网络进一步为客户赋能，实现真正的门到门空运解决方案——从始发地提货到目的地最终交付。这种无与伦比的组合使我们能够为全球所有主要目的地提供可靠的快速服务、极具竞争力的价格和完全的控制。无论您需要标准空运还是专业化的敏感货物物流，我们量身定制的解决方案都能确保您的货物在每一步都快速、安全、高效地运输。",
        "Why Choose Our Air Freight Services?": "为什么选择我们的空运服务？",
        "Aggressive, Competitive Rates:": "极具竞争力的价格：",
        "Leverage our airline relationships for the best pricing to key global hubs.": "利用我们与航空公司的关系，为主要全球枢纽提供最优惠的价格。",
        "Faster Transit Times:": "更快的运输时间：",
        "Priority access ensures your cargo arrives on schedule—every time.": "优先处理权确保您的货物每次都能准时到达。",
        "Advanced Cold Chain & Temperature Control:": "先进的冷链与温控：",
        "We handle reefer, temperature-sensitive, and active container (Envirotainer) shipments with expertise.": "我们专业处理冷藏、温敏和主动式（Envirotainer）集装箱的运输。",
        "Specialized Cargo Handling:": "专业货物处理：",
        " From DGR (dangerous goods) to valuables, pets/live animals, and human remains—our team handles it all with care and compliance.": "从DGR（危险品）到贵重物品、宠物/活体动物和遗体——我们的团队都能谨慎合规地处理。",
        "End-to-End Service:": "端到端服务：",
        "Receive comprehensive solutions including pickup/delivery, packing, labelling, documentation, insurance, and customs clearance.": "获得全面的解决方案，包括提货/送货、包装、贴标、文件、保险和清关。",
        "Additional Capabilities": "附加能力",
        "Cargo consolidation for cost efficiency to key destinations.": "货物拼箱，以提高到关键目的地的成本效益。",
        "Expert handling of personal effects, household goods, and chartered flight operations.": "专业处理个人物品、家居用品和包机业务。",
        "Full spectrum of value-added services with and expert support at every step.": "全方位的增值服务，并在每一步提供专家支持。",

        //OCEAN_FREIGHT
        "OCEAN_FREIGHT_TITLE": "海运（进出口服务）",
        "OCEAN_FREIGHT_DESC": "多年来我们与各大船运公司建立的良好信誉和稳固的合作伙伴关系，使我们能够提供全面的海运解决方案，满足进出口业务的严格时间限制。我们的专业知识涵盖整个海运物流领域，从标准集装箱运输到复杂的项目货物，并由优秀的海外代理支持，确保全球无缝的门到门派送。",
        "WHY_CHOOSE_OCEAN_FREIGHT_TITLE": "为什么选择我们的海运服务？",
        "OCEAN_FREIGHT_FEATURE_1_TITLE": "全面的整箱和拼箱解决方案：",
        "OCEAN_FREIGHT_FEATURE_1_DESC": "通过我们与船运公司建立的合作关系，为整箱和拼箱货物提供灵活的订舱选择和有竞争力的价格。",
        "OCEAN_FREIGHT_FEATURE_2_TITLE": "专业货物专长：",
        "OCEAN_FREIGHT_FEATURE_2_DESC": "专业处理 ODC（超尺寸货物）、项目货物、危险品和带温控解决方案的冷藏货物。",
        "OCEAN_FREIGHT_FEATURE_3_TITLE": "端到端服务集成：",
        "OCEAN_FREIGHT_FEATURE_3_DESC": "完整的物流管理，包括清关、包装、打托、海运保险以及 DDU/DDP 处理。",
        "OCEAN_FREIGHT_FEATURE_4_TITLE": "全球网络和贸易航线专业化：",
        "OCEAN_FREIGHT_FEATURE_4_DESC": "广泛的海外代理网络确保在专业贸易航线上提供可靠的服务和本地专业知识。",
        "OCEAN_FREIGHT_FEATURE_5_TITLE": "海运增值服务：",
        "OCEAN_FREIGHT_FEATURE_5_DESC": "全面支持，包括拼箱/拆箱、仓储、配送、运输和个人物品处理，实现完整的供应链管理。",

        //CUSTOMS_BROKERAGE
        "CUSTOMS_BROKERAGE_TITLE": "报关服务",
        "CUSTOMS_BROKERAGE_DESC": "应对复杂的国际贸易法规需要专业的报关服务，以确保您的出口货物能够迅速、合规地清关。作为拥有深厚法规专业知识的AEO认证报关行，我们简化整个海关流程，最大限度地减少延误，并为各行各业的企业优化关税成本。",
        "WHY_CHOOSE_CUSTOMS_BROKERAGE_TITLE": "为什么选择我们的报关服务？",
        "CUSTOMS_BROKERAGE_FEATURE_1_TITLE": "AEO认证专业知识：",
        "CUSTOMS_BROKERAGE_FEATURE_1_DESC": "经认证的经营者（AEO）身份可确保更快、更可信的海关处理，并减少查验。",
        "CUSTOMS_BROKERAGE_FEATURE_2_TITLE": "完全符合法规：",
        "CUSTOMS_BROKERAGE_FEATURE_2_DESC": "全面的文件管理、关税分类，并遵守所有进出口法规。",
        "CUSTOMS_BROKERAGE_FEATURE_3_TITLE": "关税与成本优化：",
        "CUSTOMS_BROKERAGE_FEATURE_3_DESC": "战略性的关税分类和贸易协定的利用，以最大限度地减少关税和费用。",
        "CUSTOMS_BROKERAGE_FEATURE_4_TITLE": "专业货物处理：",
        "CUSTOMS_BROKERAGE_FEATURE_4_DESC": "专家级清关服务，处理危险材料、受限货物和高价值货物，并确保合规。",
        "CUSTOMS_BROKERAGE_FEATURE_5_TITLE": "端到端支持：",
        "CUSTOMS_BROKERAGE_FEATURE_5_DESC": "从文件准备到最终交付的全面服务。",

        //WAREHOUSE
        "WAREHOUSE_TITLE": "仓储与配送服务",
        "WAREHOUSE_DESC": "在东方货运（印度）私人有限公司，我们通过提供根据您需求量身定制的专用和共享仓储与配送服务，确保您的供应链无缝运作。我们经验丰富的协作团队在运输的每个阶段提供强有力的支持，从仓储到最终交付，高效地管理您的货物。无论您需要短期还是长期存储，我们都提供安全、有序的设施，配备了打托、包装、收缩包装和贴标设备。我们战略性的仓储网络能够快速、可靠地连接主要贸易路线，确保您的产品每次都能准时送达客户手中。我们还处理熏蒸等特殊要求，以维持产品安全标准并遵守国际法规。",

        //AIR_CHARTER
        "AIR_CHARTER_TITLE": "空中包机服务",
        "AIR_CHARTER_DESC": "自1989年以来，东方货运一直专注于为时间紧迫和特殊的货物提供紧急而全面的航空货运包机服务。我们的专业团队经过专业培训，能够处理复杂的货物——从疫情期间的救生药品到超大型工业设备——确保您的货物以无与伦比的速度、安全性和灵活性送达。我们提供整机和部分包机选项，让您完全控制运输过程，并提供端到端的管理，包括飞机定位、处理、海关协调以及在印度所有主要机场的机场到机场交付。",
        "WHY_CHOOSE_AIR_CHARTER_TITLE": "为什么选择我们的空中包机服务？",
        "AIR_CHARTER_FEATURE_1_TITLE": "定制包机选项：",
        "AIR_CHARTER_FEATURE_1_DESC": "整机或部分包机，单程或往返，根据您的日程安排和货物要求量身定制。",
        "AIR_CHARTER_FEATURE_2_TITLE": "紧急物流专业知识：",
        "AIR_CHARTER_FEATURE_2_DESC": "在严格的时间表下执行关键任务的良好记录——例如与疫情相关的药品进出口。",
        "AIR_CHARTER_FEATURE_3_TITLE": "全面处理：",
        "AIR_CHARTER_FEATURE_3_DESC": "完整的包机管理，从飞机定位到专业装载、清关和交付，均符合DGCA的指导方针。",
        "AIR_CHARTER_FEATURE_4_TITLE": "战略性机场准入：",
        "AIR_CHARTER_FEATURE_4_DESC": "在印度所有主要海关机场运营，确保快速周转和最大覆盖范围。",

        //PET_PAL
        "PET_PAL_TITLE": "您的宠物伙伴：活体动物运输",
        "PET_PAL_DESC": "无论是您心爱的猫狗，甚至是马和大象，东方货运都能确保每只宠物在旅途中得到最精心的照料。我们专业的设施、温控车辆和训练有素的动物处理团队，简化了进出港的活体动物运输流程。我们还采用最佳实践来最大限度地减少飞行压力，让您的宠物平静舒适地到达目的地。",
        "WHY_CHOOSE_PET_PAL_TITLE": "为什么选择“您的宠物伙伴”？",
        "PET_PAL_FEATURE_1_TITLE": "专业的动物处理与飞行中护理：",
        "PET_PAL_FEATURE_1_DESC": "训练有素的员工遵循IATA活体动物规定，管理装载、飞行中环境设置以及与机组人员的协调，以保障动物福利。",
        "PET_PAL_FEATURE_2_TITLE": "符合DGCA规定：",
        "PET_PAL_FEATURE_2_DESC": "通过印度主要机场的动物检疫与认证服务，安排完整的健康证明、进出口许可证和检疫清关。",
        "PET_PAL_FEATURE_3_TITLE": "符合IATA标准的容器与标签：",
        "PET_PAL_FEATURE_3_DESC": "安全、通风的容器，配有适当的缓冲、排水系统，并用英语和当地语言标注“活体动物”标签。",
        "PET_PAL_FEATURE_4_TITLE": "个性化护理计划：",
        "PET_PAL_FEATURE_4_DESC": "定制的喂养、运动和镇静方案可减轻压力，并在空运提单上提供24小时紧急联系方式。",
        "PET_PAL_FEATURE_5_TITLE": "全球服务：",
        "PET_PAL_FEATURE_5_DESC": "强大的代理网络在家中、机场或兽医设施提供安全的接送服务，确保护理的无缝衔接。",

        //EXPRESS_CARGO
        "EXPRESS_CARGO_TITLE": "时效性紧急货物运输",
        "EXPRESS_CARGO_DESC": "快递货物是我们的优质服务，用于在专家监控下，以最佳速度和效率沿着供应链运输对时间要求严格的货物。从紧急文件和贵重货物到救生药品、检测用血样、飞机备件和AOG（飞机停场）部件，我们以快速的服务窗口处理各种快递货物。我们的多式联运网络结合了空运、陆运和专业运输，确保您的货物在24-72小时内到达目的地，以满足关键需求。",
        "EXPRESS_CARGO_FEATURES_TITLE": "派送选项与服务特色",
        "EXPRESS_CARGO_FEATURE_1_TITLE": "门到门快递：",
        "EXPRESS_CARGO_FEATURE_1_DESC": "从始发地到最终目的地的完整取件和派送服务。",
        "EXPRESS_CARGO_FEATURE_2_TITLE": "机场到机场快递：",
        "EXPRESS_CARGO_FEATURE_2_DESC": "为航空货物提供快速的航站楼到航站楼服务，减少处理环节并加快清关速度。",

        //PERSONAL_EFFECTS
        "PERSONAL_EFFECTS_TITLE": "个人物品运输",
        "PERSONAL_EFFECTS_DESC": "我们专业从事安全、经济的个人物品运输。当航空公司的行李限额和超额费用威胁到您的搬家时，东方货运提供无缝的非随身行李解决方案。利用我们的全球代理网络，我们管理您家居用品的包装、报关以及门到机场和门到门的派送，让您可以专注于安顿下来，而不是运输物流。",
        "WHY_CHOOSE_PERSONAL_EFFECTS_TITLE": "为什么选择我们的个人物品运输服务？",
        "PERSONAL_EFFECTS_FEATURE_1_TITLE": "超额行李管理：",
        "PERSONAL_EFFECTS_FEATURE_1_DESC": "将超出航空公司限额的物品作为非随身行李进行整合和运输，从而免除高额费用。",
        "PERSONAL_EFFECTS_FEATURE_2_TITLE": "门到门覆盖：",
        "PERSONAL_EFFECTS_FEATURE_2_DESC": "通过我们广泛的代理网络，从您家中安全取件并派送到全球任何地址。",
        "PERSONAL_EFFECTS_FEATURE_3_TITLE": "专业包装与贴标：",
        "PERSONAL_EFFECTS_FEATURE_3_DESC": "专业的装箱、缓冲和贴标技术，保护易碎物品在运输过程中的安全。",
        "PERSONAL_EFFECTS_FEATURE_4_TITLE": "海关与文件处理：",
        "PERSONAL_EFFECTS_FEATURE_4_DESC": "完整的文书工作和清关手续，以防止延误并确保合规。",
        "PERSONAL_EFFECTS_FEATURE_5_TITLE": "端到端支持：",
        "PERSONAL_EFFECTS_FEATURE_5_DESC": "从始发地到最终交付的实时货运更新和专属客户服务。",

        //HEALTHCARE_LOGISTICS
        "HEALTHCARE_LOGISTICS_TITLE": "医疗物流",
        "HEALTHCARE_LOGISTICS_SUBTITLE": "自1987年以来，精准、悉心地守护健康",
        "HEALTHCARE_TRUST_TITLE": "值得信赖的医疗物流",
        "HEALTHCARE_TRUST_DESC": "在医疗保健领域，每一次运输都至关重要。在东方货运，我们深知生命可能取决于您医疗产品的安全、快速和精确交付。因此，我们提供专为医疗保健和生命科学行业独特需求而设计的专业物流解决方案。",
        "HEALTHCARE_FEATURE_1_TITLE": "温控运输：",
        "HEALTHCARE_FEATURE_1_DESC": "为冷冻、冷藏和室温控制的货物提供经过验证的包装和冷链解决方案。",
        "HEALTHCARE_FEATURE_2_TITLE": "时效性强的交付：",
        "HEALTHCARE_FEATURE_2_DESC": "为紧急货物提供优先处理，并提供当日达和下一航班出港选项。",
        "HEALTHCARE_FEATURE_3_TITLE": "法规合规：",
        "HEALTHCARE_FEATURE_3_DESC": "协助处理贸易、海关和行业法规。",
        "HEALTHCARE_FEATURE_4_TITLE": "样品和设备处理：",
        "HEALTHCARE_FEATURE_4_DESC": "从诊断样品和临床试验套件到手术器械和药品。",
        "WHY_CHOOSE_HEALTHCARE_TITLE": "为什么医疗保健领导者选择东方货运：",
        "WHY_CHOOSE_HEALTHCARE_POINT_1": "✓ 专业的医疗物流专家。",
        "WHY_CHOOSE_HEALTHCARE_POINT_2": "✓ 覆盖全国和国际的多式联运解决方案。",
        "WHY_CHOOSE_HEALTHCARE_POINT_3": "✓ 全天候运营支持和应急预案。",
        "WHY_CHOOSE_HEALTHCARE_POINT_4": "✓ 为敏感货物提供安全的监管链协议。",
        "HEALTHCARE_CLOSING_1": "当精准与可靠至关重要时——请选择东方货运。",
        "HEALTHCARE_CLOSING_2": "立即联系我们的医疗物流团队，讨论您的需求。",
        "PASSION_TITLE": "对时效性货物的热情",
        "PASSION_DESC": "自1987年以来，我们在处理时效性强的货物方面拥有悠久的历史，为医药物流带来了无与伦比的专业知识。我们的团队以成功管理高价值的生命科学产品而闻名，包括临床试验货物、新产品发布以及向特殊和具有挑战性的地区交付。",
        "PASSION_FEATURE_1_TITLE": "专注于医药的操作：",
        "PASSION_FEATURE_1_DESC": "一支专门处理各类生命科学产品细微差别的专业团队。",
        "PASSION_FEATURE_2_TITLE": "质量与合规：",
        "PASSION_FEATURE_2_DESC": "对质量管理、卓越运营和卓越报关能力的承诺，确保您的货物符合所有监管标准。",
        "PASSION_FEATURE_3_TITLE": "温控解决方案：",
        "PASSION_FEATURE_3_DESC": "我们提供主动和被动两种医药解决方案，以保持您货物的严格温度完整性。",
        "PASSION_FEATURE_4_TITLE": "与承运商建立的稳固关系：",
        "PASSION_FEATURE_4_DESC": "与航空公司和船运公司超过30年的牢固合作关系，保证了可靠性、优先权和客户舒适度。",
        "TEMP_SOLUTIONS_TITLE": "我们的温控解决方案",
        "ENVIROTAINERS_TITLE": "温控集装箱 (主动式)",
        "ENVIROTAINERS_DESC": "我们提供最先进的主动式温控集装箱解决方案，例如 Envirotainer RKN e1 和 RAP e2，它们使用基于压缩机的冷却和电加热技术，无论环境条件如何，都能将产品精确地保持在+2°C至+8°C或+15°C至+25°C的温度范围内。",
        "THERMAL_BLANKETS_TITLE": "保温毯 (被动式)",
        "THERMAL_BLANKETS_DESC": "为防止因阳光直射或环境条件引起的温度骤升，我们将所有对温度敏感的托盘都用高质量的保温毯包裹起来。这可以在运输过程中保持所需的温度范围，确保药品保持有效和使用安全。",
        "COOL_BOXES_TITLE": "冷藏箱 (被动式)",
        "COOL_BOXES_DESC": "对于需要更严格温度控制的产品，我们使用专门的冷藏箱。这些是药品包装的重要组成部分，专门设计用于在运输和储存过程中保持疫苗、胰岛素和血液制品等敏感产品的温度。",

        //DGR
        "DGR_TITLE": "危险品运输",
        "DGR_SUBTITLE": "危险品、化学品和有害物质运输 – 专业物流解决方案",
        "DGR_DESC": "运输危险品（DG）、化学品和有害材料是一个专业领域，要求极高的精确度、专业知识和严格遵守国际安全标准。在东方货运，我们为您的货物提供全面的危险品物流解决方案，确保其通过空运、海运和陆路安全运输。",
        "DGR_SERVICES_TITLE": "我们的危险品、化学品和有害物质物流服务",
        "DGR_FEATURE_1_TITLE": "分类与识别：",
        "DGR_FEATURE_1_DESC": "根据IATA和当地法规，准确分类化学品和危险货物。我们为每批货物分配正确的联合国编号、危险类别和包装组别。",
        "DGR_FEATURE_2_TITLE": "认证包装与标签：",
        "DGR_FEATURE_2_DESC": "所有物品均由经过培训的人员使用符合危险品规定的材料进行包装、标记和贴标，以防止泄漏、溢出和事故。遵守国际标准是我们对每种运输方式的优先考虑。",
        "DGR_FEATURE_3_TITLE": "法规文件与合规：",
        "DGR_FEATURE_3_DESC": "我们管理全部文件——危险品申报单、安全数据表（SDS/MSDS）、许可证和保险——确保完美遵守IATA的法规。",
        "DGR_FEATURE_4_TITLE": "专业处理与安全运输：",
        "DGR_FEATURE_4_DESC": "您的危险货物由使用危险品认证容器的认证专业人员管理。",
        "DGR_FEATURE_5_TITLE": "端到端危险品物流支持：",
        "DGR_FEATURE_5_DESC": "从风险评估和法规咨询到运输安排、交付和安全仓储的全方位服务。",
        "DGR_CTA_1": "准备好运输您的危险品、化学品或有害材料了吗？",
        "DGR_CTA_2": "立即联系我们经过认证的危险品物流团队，获取个性化报价和全球危险品运输合规的专家指导。",
        "DGR_QUOTE_TITLE": "获取您的危险品运输免费报价",
        "DGR_QUOTE_SUBTITLE": "立即联系我们的危险品专家以获取：",
        "DGR_QUOTE_POINT_1": "关于危险品运输要求的免费咨询",
        "DGR_QUOTE_POINT_2": "从印度出口危险品的文件协助。",
        "DGR_QUOTE_POINT_3": "印度危险货物服务的有竞争力的价格。",
        "DGR_QUOTE_POINT_4": "为您的危险品物流需求提供全天候支持。",

        //PROJECT_LOGISTICS
        "PROJECT_LOGISTICS_TITLE": "项目物流",
        "PROJECT_LOGISTICS_SUBTITLE": "复杂项目货物和重型设备运输的专业解决方案",
        "PROJECT_CARGO_SOLUTIONS_TITLE": "端到端项目货物解决方案",
        "PROJECT_CARGO_SOLUTIONS_DESC": "我们的项目物流部门专门处理工业项目、发电厂、石油和天然气设施以及基础设施开发的复杂、超大和重型设备运输。凭借数十年的经验，我们确保从工厂到最终目的地的无缝协调。",
        "OUR_PROJECT_LOGISTICS_SERVICES_TITLE": "我们的项目物流服务",
        "PROJECT_SERVICE_1_TITLE": "重型设备运输：",
        "PROJECT_SERVICE_1_DESC": "专业处理机械、涡轮机、发电机和工业设备，提供定制的板条箱和安全的运输。",
        "PROJECT_SERVICE_2_TITLE": "超大货物解决方案：",
        "PROJECT_SERVICE_2_DESC": "专业管理需要特殊许可证、路线勘测和专业运输设备的超大货物运输。",
        "PROJECT_SERVICE_3_TITLE": "项目协调：",
        "PROJECT_SERVICE_3_DESC": "全面的项目管理，包括文件、清关、保险和实时跟踪。",
        "PROJECT_SERVICE_4_TITLE": "多式联运：",
        "PROJECT_SERVICE_4_DESC": "为复杂的项目需求无缝整合空运、海运和陆运方式。",
        "PROJECT_SERVICE_5_TITLE": "现场交付与安装：",
        "PROJECT_SERVICE_5_DESC": "现场交付协调、设备定位和安装支持服务。",
        "INDUSTRIES_WE_SERVE_TITLE": "我们服务的行业",
        "INDUSTRY_1_TITLE": "石油和天然气",
        "INDUSTRY_1_DESC": "管道设备、钻井机械和炼油厂组件",
        "INDUSTRY_2_TITLE": "发电",
        "INDUSTRY_2_DESC": "涡轮机、发电机、变压器和发电厂设备",
        "INDUSTRY_3_TITLE": "制造业",
        "INDUSTRY_3_DESC": "生产线、工业机械和制造设备",
        "INDUSTRY_4_TITLE": "基础设施",
        "INDUSTRY_4_DESC": "建筑设备、桥梁组件和基础设施材料。",

        //Human Remains
        'HUMAN_REMAINS_TITLE': '遗体运输服务',
        'HUMAN_REMAINS_DESC': '东方货运公司 (Eastern Cargo Carriers) 以最崇高的尊严和尊重，提供专业且富有人文关怀的遗体运输服务。我们经验丰富的团队深知此类服务的敏感性，确保运输过程的每一个环节都得到谨慎、专业和完全保密的处理。我们为国内和国际遗体运输提供全面的解决方案，包括所有必要的文件、清关和法规遵从。',
        'WHY_CHOOSE_HUMAN_REMAINS_TITLE': '为何选择我们的遗体运输服务？',
        'HUMAN_REMAINS_FEATURE_1_TITLE': '人文关怀服务:',
        'HUMAN_REMAINS_FEATURE_1_DESC': '我们的团队充分理解此类服务的情感特殊性，以敏感和尊重的方式处理一切事宜。',
        'HUMAN_REMAINS_FEATURE_2_TITLE': '文件齐全:',
        'HUMAN_REMAINS_FEATURE_2_DESC': '我们处理所有必要的文件，包括死亡证明、防腐证明、运输许可证和海关文件。',
        'HUMAN_REMAINS_FEATURE_3_TITLE': '国际专业知识:',
        'HUMAN_REMAINS_FEATURE_3_DESC': '拥有关于国际法规、航空公司要求以及目的地国家遗体运输协议的专业知识。',
        'HUMAN_REMAINS_FEATURE_4_TITLE': '24/7 支持:',
        'HUMAN_REMAINS_FEATURE_4_DESC': '提供全天候协助与协调，确保及时和有尊严的运输服务。',
        'HUMAN_REMAINS_FEATURE_5_TITLE': '法规遵从:',
        'HUMAN_REMAINS_FEATURE_5_DESC': '完全遵守国际航空运输协会（IATA）规定、国际卫生要求以及目的地国家的进出口法规。',
        'SERVICES_INCLUDED_TITLE': '我们的服务包括:',
        'SERVICE_1_TITLE': '国际遗体送返:',
        'SERVICE_1_DESC': '提供完整的国际遗体运输服务，包括所有必要的文件和清关手续。',
        'SERVICE_2_TITLE': '国内运输:',
        'SERVICE_2_DESC': '在印度全境提供可靠的国内遗体运输服务，并妥善处理和准备相关文件。',
        'SERVICE_3_TITLE': '文件协助:',
        'SERVICE_3_DESC': '全面协助处理所有必需文件，包括死亡证明、防腐证明和运输许可证。',
        'SERVICE_4_TITLE': '清关服务:',
        'SERVICE_4_DESC': '为国际遗体运输提供专业的清关服务，并完全遵守相关法规。',
        'SERVICE_5_TITLE': '航空公司协调:',
        'SERVICE_5_DESC': '直接与航空公司协调，确保遗体得到妥善处理和及时运输。'
    }
    // ... existing code ...
};

// Function to change language
function changeLanguage(lang) {
    let translatedCount = 0;
    let totalElements = 0;
    
    // Handle regular text elements
    const elements = document.querySelectorAll('[data-translate]');
    totalElements += elements.length;
    elements.forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[lang] && translations[lang][key]) {
            element.textContent = translations[lang][key];
            translatedCount++;
        } else {
            console.warn(`Missing translation for key: ${key} in language: ${lang}`);
        }
    });
    
    // Handle placeholder translations
    const placeholderElements = document.querySelectorAll('[data-translate-placeholder]');
    totalElements += placeholderElements.length;
    placeholderElements.forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        if (translations[lang] && translations[lang][key]) {
            element.placeholder = translations[lang][key];
            translatedCount++;
        } else {
            console.warn(`Missing placeholder translation for key: ${key} in language: ${lang}`);
        }
    });
    
    // Handle select options
    const selectOptions = document.querySelectorAll('option[data-translate]');
    totalElements += selectOptions.length;
    selectOptions.forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[lang] && translations[lang][key]) {
            element.textContent = translations[lang][key];
            translatedCount++;
        }
    });
    
    // Update language selector
    const langText = document.querySelector('.language-selector span');
    if (langText) {
        langText.innerHTML = `<i class="fas fa-flag"></i> ${lang.toUpperCase()} <i class="fas fa-chevron-down"></i>`;
    }
    
    // Store selected language
    localStorage.setItem('selectedLanguage', lang);

    document.documentElement.lang = lang;
    
    // Close modal
    if (languageModal) {
        languageModal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
    
    // Show notification with translation statistics
    const successRate = totalElements > 0 ? Math.round((translatedCount / totalElements) * 100) : 0;
    showNotification(`Language changed to ${lang.toUpperCase()}. ${translatedCount}/${totalElements} elements translated (${successRate}% complete)`, 'success');
    
    // Log translation statistics
    console.log(`Language change to ${lang}: ${translatedCount}/${totalElements} elements translated (${successRate}% complete)`);
}

// Language option click handlers
languageOptions.forEach(option => {
    option.addEventListener('click', () => {
        const lang = option.getAttribute('data-lang');
        changeLanguage(lang);
    });
});

// Load saved language on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedLang = localStorage.getItem('selectedLanguage');
    if (savedLang && translations[savedLang]) {
        changeLanguage(savedLang);
    }
});

// Intersection Observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('loaded');
        }
    });
}, observerOptions);

// Observe elements for animation
document.addEventListener('DOMContentLoaded', () => {
    const animateElements = document.querySelectorAll('.feature-card, .service-card, .project-card, .testimonial-card');
    animateElements.forEach(el => {
        el.classList.add('loading');
        observer.observe(el);
    });
});

// Newsletter form handling
const newsletterForm = document.querySelector('.newsletter-form');
if (newsletterForm) {
    newsletterForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const email = this.querySelector('input[type="email"]').value;
        
        if (!email) {
            showNotification('Please enter your email address.', 'error');
            return;
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showNotification('Please enter a valid email address.', 'error');
            return;
        }
        
        showNotification('Thank you for subscribing to our newsletter!', 'success');
        this.reset();
    });
}

// Notification system
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => notification.remove());
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close">&times;</button>
        </div>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#27ae60' : type === 'error' ? '#e74c3c' : '#ffa500'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 10000;
        max-width: 400px;
        animation: slideInRight 0.3s ease;
    `;
    
    // Add animation styles
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        .notification-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .notification-close {
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            margin-left: 1rem;
        }
        .notification-close:hover {
            opacity: 0.8;
        }
    `;
    document.head.appendChild(style);
    
    // Add to page
    document.body.appendChild(notification);
    
    // Close button functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.remove();
    });
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Counter animation for stats
function animateCounters() {
    const counters = document.querySelectorAll('.stat h4, .partner-stat h4');
    
    counters.forEach(counter => {
        const target = parseInt(counter.textContent.replace(/[^\d]/g, ''));
        const increment = target / 100;
        let current = 0;
        
        const updateCounter = () => {
            if (current < target) {
                current += increment;
                counter.textContent = Math.ceil(current) + (counter.textContent.includes('K') ? 'K' : '') + (counter.textContent.includes('B') ? 'B' : '');
                requestAnimationFrame(updateCounter);
            } else {
                counter.textContent = target + (counter.textContent.includes('K') ? 'K' : '') + (counter.textContent.includes('B') ? 'B' : '');
            }
        };
        
        updateCounter();
    });
}

// Trigger counter animation when about section is visible
const aboutSection = document.querySelector('.about');
if (aboutSection) {
    const aboutObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounters();
                aboutObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });
    
    aboutObserver.observe(aboutSection);
}

// Video placeholder click handler
const videoPlaceholder = document.querySelector('.video-placeholder');
if (videoPlaceholder) {
    videoPlaceholder.addEventListener('click', () => {
        showNotification('Video player would open here in a real implementation.', 'info');
    });
}

// Service cards hover effect
document.querySelectorAll('.service-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-10px) scale(1.02)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0) scale(1)';
    });
});

// Project cards click handler
document.querySelectorAll('.project-card .btn-outline').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault();
        showNotification('Project details would open here in a real implementation.', 'info');
    });
});

// Newsletter form enhancement
const newsletterInput = document.querySelector('.newsletter-form input');
if (newsletterInput) {
    newsletterInput.addEventListener('focus', function() {
        this.parentElement.style.transform = 'scale(1.02)';
    });
    
    newsletterInput.addEventListener('blur', function() {
        this.parentElement.style.transform = 'scale(1)';
    });
}

// Contact form enhancement
document.querySelectorAll('.contact-form input, .contact-form select, .contact-form textarea').forEach(input => {
    input.addEventListener('focus', function() {
        this.parentElement.style.transform = 'scale(1.02)';
    });
    
    input.addEventListener('blur', function() {
        this.parentElement.style.transform = 'scale(1)';
    });
});

// Parallax effect for hero section
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const hero = document.querySelector('.hero');
    if (hero) {
        const rate = scrolled * -0.5;
        hero.style.transform = `translateY(${rate}px)`;
    }
});

// Loading animation
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
    
    // Add loading animation to elements
    const elements = document.querySelectorAll('.feature-card, .service-card, .project-card');
    elements.forEach((el, index) => {
        setTimeout(() => {
            el.classList.add('loaded');
        }, index * 100);
    });
});

// Back to top button
const backToTopBtn = document.createElement('button');
backToTopBtn.innerHTML = '<i class="fas fa-angle-double-up"></i>';
backToTopBtn.className = 'back-to-top';
backToTopBtn.style.cssText = `
    position: fixed;
    bottom: 30px;
    right: 30px;
    width: 50px;
    height: 50px;
    background: #ffa500;
    color: white;
    border: none;
    border-radius: 50%;
    cursor: pointer;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s ease;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(255, 165, 0, 0.3);
`;

document.body.appendChild(backToTopBtn);

// Show/hide back to top button
window.addEventListener('scroll', () => {
    if (window.pageYOffset > 300) {
        backToTopBtn.style.opacity = '1';
        backToTopBtn.style.visibility = 'visible';
    } else {
        backToTopBtn.style.opacity = '0';
        backToTopBtn.style.visibility = 'hidden';
    }
});

// Back to top functionality
backToTopBtn.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

// Add hover effect to back to top button
backToTopBtn.addEventListener('mouseenter', () => {
    backToTopBtn.style.transform = 'scale(1.1)';
    backToTopBtn.style.background = '#e69500';
});

backToTopBtn.addEventListener('mouseleave', () => {
    backToTopBtn.style.transform = 'scale(1)';
    backToTopBtn.style.background = '#ffa500';
});


// Back to bottom button
const backToBottomBtn = document.createElement('button');
backToBottomBtn.innerHTML = '<i class="fas fa-angle-double-down"></i>';
backToBottomBtn.className = 'back-to-bottom';
backToBottomBtn.style.cssText = `
    position: fixed;
    bottom: 90px;
    right: 30px;
    width: 50px;
    height: 50px;
    background: #ffa500;
    color: white;
    border: none;
    border-radius: 50%;
    cursor: pointer;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s ease;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(255, 165, 0, 0.3);
`;

document.body.appendChild(backToBottomBtn);

// Show/hide back to bottom button
window.addEventListener('scroll', () => {
    const scrollPosition = window.pageYOffset + window.innerHeight;
    const pageHeight = document.documentElement.scrollHeight;

    if (scrollPosition < pageHeight - 300) {
        backToBottomBtn.style.opacity = '1';
        backToBottomBtn.style.visibility = 'visible';
    } else {
        backToBottomBtn.style.opacity = '0';
        backToBottomBtn.style.visibility = 'hidden';
    }
});

// Scroll to bottom functionality
backToBottomBtn.addEventListener('click', () => {
    window.scrollTo({
        top: document.documentElement.scrollHeight,
        behavior: 'smooth'
    });
});

// Hover effects
backToBottomBtn.addEventListener('mouseenter', () => {
    backToBottomBtn.style.transform = 'scale(1.1)';
    backToBottomBtn.style.background = '#e69500';
});

backToBottomBtn.addEventListener('mouseleave', () => {
    backToBottomBtn.style.transform = 'scale(1)';
    b
backToBottomBtn.style.background = '#ffa500';
});

// Initialize tooltips for better UX
function initTooltips() {
    const elements = document.querySelectorAll('[data-tooltip]');
    elements.forEach(element => {
        element.addEventListener('mouseenter', (e) => {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = e.target.dataset.tooltip;
            tooltip.style.cssText = `
                position: absolute;
                background: #333;
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                z-index: 10000;
                pointer-events: none;
                white-space: nowrap;
            `;
            
            document.body.appendChild(tooltip);
            
            const rect = e.target.getBoundingClientRect();
            tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
            tooltip.style.top = rect.top - tooltip.offsetHeight - 10 + 'px';
        });
        
        element.addEventListener('mouseleave', () => {
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) tooltip.remove();
        });
    });
}

// Initialize tooltips when DOM is loaded
document.addEventListener('DOMContentLoaded', initTooltips);

// Key Personnel Filter
const personnelSection = document.getElementById('personnel');
if (personnelSection) {
    const personnelData = [
        { name: "Mr Lalit Seth", title: "Director", tel: "91-22-67539906", email: "lseth@easterncargo.co.in", location: "mumbai" },
        { name: "Mr Alok Seth", title: "Director", tel: "91-22-67539924", email: "aseth@easterncargo.co.in", location: "mumbai" },
        { name: "Mr Dinyar Nadirshaw", title: "President - Projects & General Freight", tel: "91-22-67539991", email: "dinyar@easterncargo.co.in", location: "mumbai" },
        /*{ name: "Mr Suraj lal", title: "Head-Projects", tel: "91-22-67539992", email: "suraj@easterncargo.co.in", location: "mumbai" },*/
        { name: "Mrs Vidya Joshi", title: "Sr Manager Finance & Accounts", tel: "91-22-67539915", email: "vjoshi@easterncargo.co.in", location: "mumbai" },
        { name: "Ms Rita D'silva", title: "Sr Manager Freight", tel: "91-22-67539934", email: "rdsilva@easterncargo.co.in", location: "mumbai" },
        { name: "Mrs Henrika Dsouza", title: "Manager Air Freight", tel: "91-22-67539904", email: "hdsouza@easterncargo.co.in", location: "mumbai" },
        { name: "Mr Tarique Khan", title: "Associate Vice President", tel: "91-22-67539948", email: "tarique@easterncargo.co.in", location: "mumbai" },
        { name: "Kiran K", title: "Asst Manager Operations", tel: "080-41258518", email: "customercare.blr@easterncargo.co.in", location: "bangalore" },
        { name: "Mr Ramesh Kannan", title: "Branch In Charge", tel: "044-42617077", email: "rkannan@easterncargo.co.in", location: "chennai" },
        { name: "Mr Rudra Singh", title: "Branch In-charge", tel: "91-11-32908070", email: "ops.del@easterncargo.co.in", location: "delhi" },
        { name: "Mr Shubham Sharma", title: "Sales", tel: "91-0731-407666", email: "eccindoresales@easterncargo.co.in", location: "indore" },
        { name: "Mr Mukesh Mordani", title: "Sales Manager", tel: "91-79-26564417", email: "sales.amd@easterncargo.co.in", location: "ahmedabad" },
        { name: "Mr Jagadishwar.G", title: "Branch In-Charge", tel: "91-40-29550638", email: "cs.hyd@easterncargo.co.in", location: "hyderabad" },
        { name: "Mr Aanjney Agarwal", title: "Branch In Charge", tel: "+913340617182", email: "aagarwal@easterncargo.co.in", location: "kolkata" }
    ];
    const filterContainer = personnelSection.querySelector('.personnel-filter-container');
    const grid = personnelSection.querySelector('.personnel-grid');

    function renderPersonnel(location) {
        if (!grid) return;
        grid.innerHTML = '';
        personnelData.filter(p => p.location === location).forEach(p => {
            const card = document.createElement('div');
            card.className = 'personnel-card';
            card.innerHTML = `
                <div class="card-body">
                    <h4>${p.name}</h4>
                    <p>${p.title}</p>
                </div>
                <div class="card-footer">
                    <a href="tel:${p.tel.replace(/\s/g, '')}">${p.tel}</a>
                    <a href="mailto:${p.email}">${p.email}</a>
                </div>
            `;
            grid.appendChild(card);
        });
    }

    if (filterContainer) {
        filterContainer.addEventListener('click', function (e) {
            if (e.target.tagName === 'BUTTON') {
                if (filterContainer.querySelector('.active')) {
                    filterContainer.querySelector('.active').classList.remove('active');
                }
                e.target.classList.add('active');
                renderPersonnel(e.target.dataset.filter);
            }
        });
    }
    renderPersonnel('mumbai');
}

// Smart Cargo Calculator
const calculator = document.getElementById('calculator');
if (calculator) {
    const unitToggleButtons = calculator.querySelectorAll('.unit-toggle-btn');
    const packageList = calculator.querySelector('#package-list');
    const addPackageBtn = calculator.querySelector('#add-package-btn');
    const calculateBtn = calculator.querySelector('#calculate-btn');
    const resultDisplay = calculator.querySelector('#result-display');
    const resetBtn = calculator.querySelector('#reset-btn');
    let currentUnit = 'IN';
    let packageCount = 0;
    const VOLUMETRIC_DIVISOR_IN = 366;
    const VOLUMETRIC_DIVISOR_CM = 6000;

    const updatePlaceholders = () => {
        const unitName = currentUnit === 'IN' ? 'inches' : 'cm';
        packageList.querySelectorAll('input[data-type="length"]').forEach(i => i.placeholder = `Length (${unitName})`);
        packageList.querySelectorAll('input[data-type="width"]').forEach(i => i.placeholder = `Width (${unitName})`);
        packageList.querySelectorAll('input[data-type="height"]').forEach(i => i.placeholder = `Height (${unitName})`);
    };

    const createPackageElement = () => {
        packageCount++;
        const div = document.createElement('div');
        div.className = 'package-group';
        div.innerHTML = `
            <div class="package-title">
                <span>Package ${packageCount}</span>
                ${packageCount > 1 ? '<button class="btn-delete" title="Remove Package">&times;</button>' : ''}
            </div>
            <div class="package-inputs">
                <input type="number" data-type="length" min="0">
                <input type="number" data-type="width" min="0">
                <input type="number" data-type="height" min="0">
                <input type="number" data-type="quantity" value="1" min="1">
            </div>
        `;
        packageList.appendChild(div);
        updatePlaceholders();
    };

    const resetCalculator = () => {
        packageList.innerHTML = '';
        packageCount = 0;
        resultDisplay.innerHTML = '';
        resultDisplay.style.display = 'none';
        createPackageElement();
    };

    const handleUnitToggle = e => {
        if (currentUnit === e.target.dataset.unit) return;
        currentUnit = e.target.dataset.unit;
        unitToggleButtons.forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        updatePlaceholders();
        resultDisplay.innerHTML = '';
        resultDisplay.style.display = 'none';
    };

    const handleCalculation = () => {
        let totalVolume = 0;
        packageList.querySelectorAll('.package-group').forEach(g => {
            const l = parseFloat(g.querySelector('input[data-type="length"]').value) || 0;
            const w = parseFloat(g.querySelector('input[data-type="width"]').value) || 0;
            const h = parseFloat(g.querySelector('input[data-type="height"]').value) || 0;
            const q = parseInt(g.querySelector('input[data-type="quantity"]').value) || 0;
            if (l > 0 && w > 0 && h > 0 && q > 0) totalVolume += (l * w * h) * q;
        });
        if (totalVolume > 0) {
            const divisor = currentUnit === 'IN' ? VOLUMETRIC_DIVISOR_IN : VOLUMETRIC_DIVISOR_CM;
            const unitLabel = currentUnit === 'IN' ? 'lbs' : 'kg';
            const totalWeight = totalVolume / divisor;
            resultDisplay.innerHTML = `
                <h3>Calculation Result</h3>
                <p>Total Volumetric Weight: <strong>${totalWeight.toFixed(2)} ${unitLabel}</strong></p>
            `;
            resultDisplay.style.display = 'block';
        } else {
            resultDisplay.innerHTML = '<p style="color: red;">Please enter valid dimensions.</p>';
            resultDisplay.style.display = 'block';
        }
    };

    unitToggleButtons.forEach(b => b.addEventListener('click', handleUnitToggle));
    addPackageBtn.addEventListener('click', createPackageElement);
    calculateBtn.addEventListener('click', handleCalculation);
    resetBtn.addEventListener('click', resetCalculator);
    packageList.addEventListener('click', e => {
        if (e.target.classList.contains('btn-delete')) {
            e.target.closest('.package-group').remove();
        }
    });

    createPackageElement();
}

// Timeline Animation and Interactive Popouts
const timelineItems = document.querySelectorAll('.timeline-item');
if (timelineItems.length > 0) {
    const observerOptions = {
        threshold: 0.5,
        rootMargin: '0px 0px -50px 0px'
    };

    const timelineObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 200);
            }
        });
    }, observerOptions);

    timelineItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateY(30px)';
        item.style.transition = 'all 0.6s ease';
        timelineObserver.observe(item);
        
            // Add click event for mobile popout toggle
    item.addEventListener('click', function() {
        if (window.innerWidth <= 768) {
            const popup = this.querySelector('.timeline-popup');
            const allPopups = document.querySelectorAll('.timeline-popup');
            
            // Close all other popups
            allPopups.forEach(p => {
                if (p !== popup) {
                    p.style.display = 'none';
                }
            });
            
            // Toggle current popup
            if (popup.style.display === 'none' || popup.style.display === '') {
                popup.style.display = 'block';
            } else {
                popup.style.display = 'none';
            }
        }
    });
    
    // Simple popup show/hide for desktop
    item.addEventListener('mouseenter', function() {
        if (window.innerWidth > 768) {
            const popup = this.querySelector('.timeline-popup');
            popup.style.opacity = '1';
            popup.style.visibility = 'visible';
        }
    });
    
    item.addEventListener('mouseleave', function() {
        if (window.innerWidth > 768) {
            const popup = this.querySelector('.timeline-popup');
            popup.style.opacity = '0';
            popup.style.visibility = 'hidden';
        }
    });
    });
    
    // Close popups when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.timeline-item')) {
            const allPopups = document.querySelectorAll('.timeline-popup');
            allPopups.forEach(popup => {
                popup.style.display = 'none';
            });
        }
    });
}

// Feature Cards Animation
const featureCards = document.querySelectorAll('.feature-card');
if (featureCards.length > 0) {
    const featureObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 150);
            }
        });
    }, { threshold: 0.3 });

    featureCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(50px)';
        card.style.transition = 'all 0.8s ease';
        featureObserver.observe(card);
    });
}

// Service Cards Animation
const serviceCards = document.querySelectorAll('.service-card');
if (serviceCards.length > 0) {
    const serviceObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 200);
            }
        });
    }, { threshold: 0.3 });

    serviceCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(50px)';
        card.style.transition = 'all 0.8s ease';
        serviceObserver.observe(card);
    });
}

// Hero Slider
const heroSection = document.getElementById('home');
if (heroSection) {
    const slides = heroSection.querySelectorAll('.slide');
    const dotsContainer = heroSection.querySelector('.slider-dots');
    
    if (slides.length > 1) {
        let currentSlide = 0;
        let slideInterval = setInterval(nextSlide, 5000);

        // Create dots
        slides.forEach((_, index) => {
            const dot = document.createElement('div');
            dot.classList.add('dot');
            dot.addEventListener('click', () => {
                goToSlide(index);
                clearInterval(slideInterval);
                slideInterval = setInterval(nextSlide, 5000);
            });
            dotsContainer.appendChild(dot);
        });

        const dots = dotsContainer.querySelectorAll('.dot');
        
        function goToSlide(slideNumber) {
            slides[currentSlide].classList.remove('active');
            dots[currentSlide].classList.remove('active');
            currentSlide = slideNumber;
            slides[currentSlide].classList.add('active');
            dots[currentSlide].classList.add('active');
        }

        function nextSlide() {
            goToSlide((currentSlide + 1) % slides.length);
        }
        
        // Initialize first slide
        goToSlide(0);
    }
}

// Location Tabs Functionality
function initializeLocationTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    console.log('Initializing location tabs...');
    console.log('Found tab buttons:', tabButtons.length);
    console.log('Found tab panes:', tabPanes.length);

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            console.log('Tab clicked:', targetTab);
            
            // Remove active class from all buttons and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked button and corresponding pane
            button.classList.add('active');
            const targetPane = document.getElementById(targetTab);
            if (targetPane) {
                targetPane.classList.add('active');
                console.log('Activated tab:', targetTab);
            } else {
                console.error('Target pane not found:', targetTab);
            }
        });
    });
}

// Initialize location tabs when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing location tabs...');
    initializeLocationTabs();
    
    // Test: Show first tab content immediately
    setTimeout(() => {
        const firstTab = document.querySelector('.tab-pane.active');
        if (firstTab) {
            console.log('First tab content:', firstTab.innerHTML);
        }
    }, 1000);
    
    // Initialize CAPTCHA and form handling
    //initializeCaptchaAndForms();
}); 

// New Why Choose Us Section Functionality
function initializeWhyChooseNew() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    const planeContainer = document.querySelector('.plane-container');
    
    // Tab switching functionality
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all buttons and panels
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanels.forEach(panel => panel.classList.remove('active'));
            
            // Add active class to clicked button and corresponding panel
            button.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
            
            // Change plane animation based on active tab
            if (planeContainer) {
                planeContainer.style.animation = 'none';
                setTimeout(() => {
                    planeContainer.style.animation = 'planeMove 8s infinite ease-in-out';
                }, 10);
            }
        });
    });
    
    // Watch Video button functionality
    const watchVideoBtn = document.querySelector('.watch-video-btn');
    if (watchVideoBtn) {
        watchVideoBtn.addEventListener('click', () => {
            // You can add video modal or redirect to video here
            showNotification('Video feature coming soon!', 'info');
        });
    }
    
    // Learn More buttons functionality
    const learnMoreBtns = document.querySelectorAll('.learn-more-btn');
    learnMoreBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // You can add navigation or modal functionality here
            document.querySelector('#learnMoreModal').classList.add('open');
            //showNotification('Learn more feature coming soon!', 'info');
        });
    });
}

// Initialize new Why Choose Us section when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // ... existing code ...
    initializeWhyChooseNew();
});

document.addEventListener('DOMContentLoaded', function() {
    // Select all dropdown links in the main navigation
    const dropdownToggles = document.querySelectorAll('.nav-menu .nav-item.dropdown > a.nav-link');

    dropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', function(event) {
            // KEY CHANGE: This now runs on ALL screen sizes, preventing the page jump.
            event.preventDefault();

            // This logic to toggle the menu on tap is still just for mobile.
            if (window.innerWidth <= 768) {
                const dropdownMenu = this.nextElementSibling;
                if (dropdownMenu) {
                    dropdownMenu.classList.toggle('show');
                }
            }
        });
    });
});