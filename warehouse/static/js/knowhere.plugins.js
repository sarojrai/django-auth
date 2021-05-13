;(function($){

	'use strict';

	$(function(){

		/* ------------------------------------------------
				Revolution Slider
		------------------------------------------------ */

			var revSlider = $('#rev_slider');
			
			if(revSlider.length){

				revSlider.revolution({
			    	sliderType:"standard",
			    	sliderLayout:"fullwidth",
			    	spinner: false,
			    	delay: 4000,
			    	navigation: {
						arrows:{
							enable: false,
							hide_onleave: true,
							hide_onmobile: true,
							rtl: $.knowhere.ISRTL,
							tmp: '<span class="kw-arrow"></span>',
							left: {
								container:"slider",
					            h_align: $.knowhere.ISRTL ? "right" : "left",
					            v_align:"center",
					            h_offset:30,
					            v_offset:0
							},
							right: {
					            container:"slider",
					            h_align: $.knowhere.ISRTL ? "left" : "right",
					            v_align:"center",
					            h_offset:30,
					            v_offset:0
							}
						},
						bullets:{
				        	style:"",
				        	enable: false,
				        	container: "slider",
				        	rtl: $.knowhere.ISRTL,
				        	hide_onmobile: false,
				        	hide_onleave: false,
				        	hide_delay: 200,
				        	hide_under: 0,
				        	hide_over: 9999,
				        	tmp:'<span class="kw-bullet"></span>', 
				        	direction:"vertical",
				        	space: 20,       
				        	h_align: "right",
				        	v_align: "center",
				        	h_offset: 20,
				        	v_offset: 0
				        },
				        onHoverStop: "off",
				        touch:{
				         	touchenabled:"on"
				        }
					},
					gridwidth:1140,
					gridheight:720,
					disableProgressBar: "on"
			    });

			}

		/* ------------------------------------------------
				End of Revolution Slider
		------------------------------------------------ */

		/* ------------------------------------------------
				Fancybox
		------------------------------------------------ */

			if('fancybox' in $){

				$.fancybox.defaults.padding = 12;

				$.fancybox.defaults.wrapCSS = 'kw-fancybox';

				$.fancybox.defaults.openEffect = 'elastic';
				$.fancybox.defaults.closeEffect = 'elastic';

				$.fancybox.defaults.openSpeed = 500;
				$.fancybox.defaults.closeSpeed = 500;

				$.fancybox.defaults.openEasing = 'easeOutQuint';
				$.fancybox.defaults.closeEasing = 'easeOutQuint';

				$.fancybox.defaults.helpers.thumbs = {
					width: 80,
					height: 80
				}

				var fancyboxItem = $('.fancybox'),
					fancyboxMedia = $('.fancybox-media')

				if(fancyboxMedia.length){

					fancyboxMedia.fancybox({
						openEffect  : 'none',
						closeEffect : 'none',
						helpers : {
							media : {}
						}
					});

				}

				if(fancyboxItem.length){

					fancyboxItem.fancybox()

				}

			}

		/* ------------------------------------------------
				End of Fancybox
		------------------------------------------------ */

		/* ------------------------------------------------
				Custom Select
		------------------------------------------------ */

			var select = $('.kw-custom-select');

			if(select.length){
				select.MadCustomSelect({
					cssPrefix: 'kw-'
				});
			}

		/* ------------------------------------------------
				End of Custom Select
		------------------------------------------------ */

		/* ------------------------------------------------
				Main Navigation
		------------------------------------------------ */

			var nav 		 = $('.kw-navigation'),
				additinalNav = $('.kw-additional-nav');

			if(nav.length){
				nav.wtNav({
					cssPrefix: 'kw-'
				});
			}

			if(additinalNav.length){
				additinalNav.wtNav({
					cssPrefix: 'kw-'
				});
			}

		/* ------------------------------------------------
				End of Main Navigation
		------------------------------------------------ */

		/* ------------------------------------------------
				Tooltips
		------------------------------------------------ */
			var tooltips = $('[data-tooltip]');
			if(tooltips.length) {
				tooltips.wtTooltip({
					cssPrefix: 'kw-',
					activeClass: 'active',
					rtl: false,
					animateIn: 'zoomIn',
					animateOut: 'zoomOut'
				});
			}
		/* ------------------------------------------------
				End of Tooltips
		------------------------------------------------ */

		/* ------------------------------------------------
				Instagram Feed
		------------------------------------------------ */

			if($('#instafeed').length){

				var feed = new Instafeed({
						target: 'instafeed',
						tagName: 'living',
						limit: 6,
						get: 'user',
						userId: 314754609,
						accessToken: '314754609.a85626a.dbe04117a894440ebb2586a385685451',
						resolution: 'standard_resolution',
						clientId: '686d7a7385cf43ebb9518774734459da',
						template: '<div class="kw-instafeed-item"><a class="fancybox kw-lightbox" rel="instagram" href="{{image}}" title="{{location}}"><img src="{{image}}" /></a></div>',
						after: function(){
							$('#' + this.options.target).find('.fancybox').fancybox();
						}
					});
						
				feed.run();

			}

		/* ------------------------------------------------
				End of Instagram Feed
		------------------------------------------------ */

		/* ------------------------------------------------
				Twitter Feed
		------------------------------------------------ */

			var twitterFeed = $('.kw-twitter-feed');

			if(twitterFeed.length){

				twitterFeed.tweet({
					username : 'fanfbmltemplate',
					modpath: 'plugins/twitter/',
					count : 2,
					loading_text : '<p>Loading tweets...</p>',
					template : '<div class="kw-tweet">{text}{time}</div>'
				});

				var TContainer = twitterFeed.filter('.kw-twitter-carousel').find('.tweet_list');

				// init owl carousel
				if(TContainer.length){

					TContainer.addClass('owl-carousel owl-nav-position-bottom').owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
						// options here
					}));

					$.knowhere.templateHelpers.owlHelper.init(TContainer);
					

				}

				

			}

		/* ------------------------------------------------
				End of Twitter Feed
		------------------------------------------------ */

		/* ------------------------------------------------
				Owl Carousel
		------------------------------------------------ */			

			var slideshow 		  = $('.owl-carousel.kw-slideshow'),
				slideshowThumbs   = $('.owl-carousel.kw-slideshow-thumbs:not([class*="kw-type-"])'),
				slideshowThumbs2   = $('.owl-carousel.kw-slideshow-thumbs.kw-type-2'),
				recentListings    = $('.kw-listings-carousel-v1.owl-carousel'),
				listingsV2        = $('.kw-listings-carousel-v2.owl-carousel'),
				listingsV3        = $('.kw-listings-carousel-v3.owl-carousel'),
				testimonialsV1    = $('.kw-testimonials-carousel-v1.owl-carousel'),
				testimonialsV2    = $('.kw-testimonials-carousel-v2.owl-carousel'),
				testimonialsV3    = $('.kw-testimonials-carousel-v3.owl-carousel'),
				testimonialsV4    = $('.kw-testimonials-carousel-v4.owl-carousel'),
				ribbonSlider      = $('.kw-ribbon-slider.owl-carousel'),
				latestPosts  	  = $('.kw-entries.owl-carousel'),
				jobsCarousel 	  = $('.job_listings.kw-jobs-carousel .job_listings'),
				employersCarousel = $('.kw-employers.owl-carousel'),
				teamMembers 	  = $('.kw-team-members.owl-carousel'),
				partners	  	  = $('.kw-partners-carousel.owl-carousel'),
				propertySlideshow = $('.owl-carousel.kw-property-slideshow'),
				featuredProperties = $('.owl-carousel.kw-featured-properties'),
				newProperties 	  = $('.owl-carousel.kw-new-properties'),
				featuredListings  = $('.owl-carousel.kw-featured-listings');

			if(featuredProperties.length){

				var featuredPropertiesItemsConfig = {
					0: {
						items: 1
					},
					520: {
						items: 2
					},
					991: {
						items: 3
					},
					1280: {
						items: 4
					}
				},
				hasSidebar = featuredProperties.closest('.kw-section.kw-has-sidebar');

				if(hasSidebar.length){
					featuredPropertiesItemsConfig = {
						0: {
							items: 1
						},
						520: {
							items: 2
						},
						1199: {
							items: 3
						}
					}
				}

				featuredProperties.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: featuredPropertiesItemsConfig,
					margin: 30,
					nav: true,
					autoplay: false,
					loop: false, // important
					dots: false
				}));

			}

			if(featuredListings.length){

				var featuredListingsItemsConfig = {
					0: {
						items: 1
					},
					520: {
						items: 2
					},
					991: {
						items: 3
					},
					1280: {
						items: 4
					}
				},
				hasSidebar = featuredListings.closest('.kw-section.kw-has-sidebar');

				if(hasSidebar.length){
					featuredListingsItemsConfig = {
						0: {
							items: 1
						},
						520: {
							items: 2
						},
						1199: {
							items: 3
						}
					}
				}

			}

			if(listingsV2.length) {

				listingsV2.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					items: 1,
					margin: 5,
					nav: true,
					autoplay: true,
					loop: true, // important
					dots: false,
					animateIn: false,
					animateOut: false
				}));

			}

			if(listingsV3.length) {

				listingsV3.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 1
						},
						600: {
							items: 2
						},
						991: {
							items: 3
						},
						1199: {
							items: 4
						}
					},
					margin: 30,
					nav: true,
					autoplay: true,
					loop: true,
					animateIn: false,
					animateOut: false,
					dots: false,
				}));

			}

			if(ribbonSlider.length) {
				ribbonSlider.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					items: 2,
					margin: 2,
					center: true,
					nav: true,
					autoplay: true,
					loop: true,
					animateIn: false,
					animateOut: false,
					dots: false
				}));
			}


			if(newProperties.length){

				var newPropertiesItemsConfig = {
					0: {
						items: 1
					},
					520: {
						items: 2
					},
					991: {
						items: 3
					}
				},
				hasSidebar = newProperties.closest('.kw-section.kw-has-sidebar');

				if(hasSidebar.length){
					newPropertiesItemsConfig = {
						0: {
							items: 1
						},
						520: {
							items: 2
						},
						1199: {
							items: 3
						}
					}
				}

				newProperties.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: newPropertiesItemsConfig,
					margin: 30,
					nav: true,
					autoplay: false,
					loop: false, // important
					dots: false
				}));

			}

			if(employersCarousel.length){

				employersCarousel.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 1
						},
						640: {
							items: 2
						},
						991: {
							items: 3
						},
						1480: {
							items: 4
						},
						1800: {
							items: 5	
						}
					},
					margin: 30,
					nav: true,
					dots: false
				}));

			}

			if(teamMembers.length){

				teamMembers.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 1
						},
						400: {
							items: 2
						},
						640: {
							items: 3
						},
						991: {
							items: 4
						},
						1300: {
							items: 6
						}
					},
					margin: 30,
					nav: true,
					dots: true
				}));

			}

			if(jobsCarousel.length){

				jobsCarousel.addClass('owl-carousel owl-nav-position-bottom').owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(jobsCarousel.find('.kw-rating'));
					}
				}));

				$.knowhere.templateHelpers.owlHelper.init(jobsCarousel);

			}

			if(slideshow.length){

				slideshow.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					// options here
					autoplay: false, // important
					loop: false // important
				}));

			}

			if(slideshowThumbs.length){

				slideshowThumbs.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 3
						},
						320: {
							items: 4
						},
						500: {
							items: 5
						}
					},
					margin: 6,
					loop: false,
					mouseDrag: false,
					nav: false,
					dots: false
				}));

			}

			if(slideshowThumbs2.length){

				slideshowThumbs2.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 3
						},
						320: {
							items: 4
						},
						500: {
							items: 7
						}
					},
					margin: 6,
					loop: false,
					mouseDrag: false,
					nav: true,
					dots: false
				}));

			}

			if(propertySlideshow.length){

				propertySlideshow.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					autoplay: false,
					loop: false,
					mouseDrag: false,
					touchDrag: false
				}));

			}

			if(recentListings.length){

				recentListings.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					nav: true,
					dots: true,
					margin: 30,
					responsive: {
						0: {
							items: 1
						},
						620: {
							items: 2
						},
						767: {
							items: 3
						},
						991: {
							items: 4
						},
						1500: {
							items: 5
						}
					},
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(recentListings.find('.kw-rating'));
					}
				}));

			}

			if(testimonialsV1.length){

				testimonialsV1.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					dots: true,
					nav: true,
					animateIn: false,
					animateOut: false,
					items: 1,
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(testimonialsV1.find('.kw-rating'));
					}
				}));

			}

			if(testimonialsV2.length){

				testimonialsV2.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 1
						},
						767: {
							items: 2
						},
						991: {
							items: 3
						}
					},
					dots: true,
					nav: true,
					margin: 30,
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(testimonialsV2.find('.kw-rating'));
					}
				}));

			}

			if(testimonialsV3.length){

				testimonialsV3.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					items: 1,
					animateIn: false,
					animateOut: false,
					dots: true,
					nav: false,
					margin: 30,
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(testimonialsV3.find('.kw-rating'));
					}
				}));

			}

			if(testimonialsV4.length){

				testimonialsV4.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					items: 1, // important
					dots: true, // important
					loop: false, // important
					nav: false,
					onInitialized: function(){
						$.knowhere.templateHelpers.productRating(testimonialsV4.find('.kw-rating'));
					}
				}));

			}

			if(partners.length){

				partners.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					dots: true,
					nav: true,
					responsive: {
						0: {
							items: 2
						},
						620: {
							items: 3
						},
						991: {
							items: 6
						}
					}
				}));

			}

			if(latestPosts.length){

				latestPosts.owlCarousel($.extend({}, $.knowhere.templateHelpers.owlHelper.baseConfig, {
					responsive: {
						0: {
							items: 1
						},
						620: {
							items: 2
						},
						991: {
							items: 3
						}
					},
					dots: true,
					margin: 30
				}));

			}

		/* ------------------------------------------------
				Accordion
		------------------------------------------------ */

			var accordions = $('.kw-accordion');

			if(accordions.length){

				accordions.MadAccordion({
					easing: 'easeOutQuint',
					speed: 600,
					cssPrefix: 'kw-'
				});

			}

		/* ------------------------------------------------
				End of Accordion
		------------------------------------------------ */

		/* ------------------------------------------------
				Toggle
		------------------------------------------------ */

			var toggles = $('.kw-toggle');

			if(toggles.length){

				toggles.MadAccordion({
					toggle: true,
					easing: 'easeOutQuint',
					speed: 600,
					cssPrefix: 'kw-'
				});

			}

		/* ------------------------------------------------
				End of Toggle
		------------------------------------------------ */

		/* ------------------------------------------------
				Tour Sections
		------------------------------------------------ */

			var tourSections = $('.kw-tour-sections');

			if(tourSections.length){

				tourSections.MadTabs({
					easing: 'easeOutQuint',
					speed: 600,
					cssPrefix: 'kw-'
				});

			}

		/* ------------------------------------------------
				End of TourSections
		------------------------------------------------ */

		/* ------------------------------------------------
				jQuery UI Slider & Datapicker
		------------------------------------------------ */

			var $slider  = $('.kw-range-slider .kw-slider'),
				$slider2 = $('.kw-range-slider.kw-type-2 .kw-slider');

			if($slider.length){

				var range = [100, 400];

				$slider.slider({
					range: true,
					min: 0,
					max: 550,
					values: range,
					create: kwRangeSliderUpdate,
					slide: kwRangeSliderUpdate
				});

				function kwRangeSliderUpdate(event, ui){

					var $slider = $(event.target);
					if(!$slider.length) return;

					$slider = $slider.closest('form');
					if(!$slider.length) return;

					var from = ui.values && ui.values.length ? ui.values[0] : range[0],
						to   = ui.values && ui.values.length ? ui.values[1] : range[1];

					$slider.find('.kw-range-from-visual').text('$' + from);
					$slider.find('.kw-range-to-visual').text('$' + to);

					$slider.find('input.kw-range-from').val(from);
					$slider.find('input.kw-range-to').val(to);

				}

			}

			if($slider2.length){

				var fromField = $slider2.siblings('.kw-range-from'),
					toField   = $slider2.siblings('.kw-range-to');

				$slider2.slider({
					range: "min",
					min: 100,
					max: 550,
					value: 10,
					create: kwRangeSliderUpdate2,
					slide: kwRangeSliderUpdate2
				});

				fromField.on('focusout', function(){

					$slider2.slider("option", "min", +$(this).val());

				});

				toField.on('focusout', function(){

					$slider2.slider("option", "max", +$(this).val());

				});

				

				function kwRangeSliderUpdate2(event, ui){

					if(window.rangeTimeout) clearTimeout(window.rangeTimeout);

					window.rangeTimeout = setTimeout(function(){

						var $slider2 = $(event.target);
						if(!$slider2.length) return;

						$slider2 = $slider2.closest('form');
						if(!$slider2.length) return;

						var from = fromField.length ? +fromField.val() : 100,
							to   = ui.value ? ui.value : $slider2.slider('option', 'max');

						$slider2.find('.kw-range-from-visual').text('$' + from);
						$slider2.find('.kw-range-to-visual').text('$' + to);

						$slider2.find('input.kw-range-from').val(from);
						$slider2.find('input.kw-range-to').val(to);

					}, 0);

				}



			}

			var datePicker = $('#datepicker');

			if(datePicker.length) {
				datePicker.datepicker({
					defaultDate: '11/01/2016'
				});
			}

		/* ------------------------------------------------
				End of jQuery UI Slider
		------------------------------------------------ */

		/* ------------------------------------------------
				Countdown
		------------------------------------------------ */

			var $countdown = $('.kw-countdown');

			if($countdown.length){

				$countdown.each(function(){

					var $this = $(this),
						endDate = $this.data(),
						until = new Date(
							endDate.year,
							endDate.month || 0,
							endDate.day || 1,
							endDate.hours || 0,
							endDate.minutes || 0,
							endDate.seconds || 0
						);

					// initialize
					$this.countdown({
						until : until,
						format : 'dHMS',
						labels : ['years', 'month', 'weeks', 'days', 'hours', 'minutes', 'seconds']
					});

				});

			}

		/* ------------------------------------------------
				End countdown
		------------------------------------------------ */

	});

	$(window).on('load', function(){

		/* ------------------------------------------------
				WTAudio
		------------------------------------------------ */

			var $audio = $('audio');

			if($audio.length){
				
				$audio.WTAudio();

			}

		/* ------------------------------------------------
				End of WTAudio
		------------------------------------------------ */

		/* ------------------------------------------------
				Tabs
		------------------------------------------------ */

			var tabs = $('.kw-tabs');

			if(tabs.length){

				tabs.MadTabs({
					easing: 'easeOutQuint',
					speed: 600,
					cssPrefix: 'kw-'
				});

			}

		/* ------------------------------------------------
				End of Tabs
		------------------------------------------------ */

	});

})(jQuery);