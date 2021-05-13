;(function($){

	'use strict';

	$.knowhere = {

		/**
		 * Main Constants
		 **/
		ISRTL: getComputedStyle(document.body).direction === 'rtl',
		TRANSITIONDURATION: 350, // base jQuery animation duration

		FLEXBOXSUPPORTED: $('html').hasClass('kw-flexbox'),
		ISTOUCH: $('html').hasClass('kw-touchevents'),
		ANIMATIONSUPPORTED: $('html').hasClass('kw-cssanimations'),

		/**
		 * Ancillary constants
		 **/
		TRANSITIONEND : "webkitTransitionEnd otransitionend oTransitionEnd msTransitionEnd transitionend",
		ANIMATIONEND: "webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend",

		DOMReady: function(){

			// full width section init
			if($('.kw-section.kw-fw').length) this.templateHelpers.fwSection.init();
			if($('.kw-section.kw-fw-bg').length) this.templateHelpers.fwSectionBg.init();

			if($('.kw-page-header').not('.kw-type-4, .kw-type-3').length) this.templateHelpers.pageHeader.init();

			// dynamically set background image 
			if($('[data-bg]').length) this.templateHelpers.bgImage();

			if($('.owl-carousel').length) this.templateHelpers.owlHelper.init();
			
			if($('.kw-shopping-cart-full').length) this.modules.removeProduct();

			if($('.kw-file-input-field').length) this.events.fileInputField();

			// back to top button init
			this.modules.backToTop.init({
				easing: 'easeOutQuint',
				speed: 550,
				cssPrefix: 'kw-'
			});

			this.modules.modalWindows.init();
			this.modules.dropdown.init({
				'cssPrefix': 'kw-',
				'speed': 500,
				'animation-in': 'fadeInUp',
				'animation-out': 'fadeOutDown'
			});

			// close btn init
			this.modules.closeBtn();

			if($('.kw-gmap').length) this.modules.googleMaps();

			// initialization of the WP Job manager plugin
			if($('.kw-listings').length) this.modules.JobManager.init();

			// Please comment or remove this initialization in case with using WP contactForm7
			if($('.kw-contact-form').length) this.modules.contactForm.init();
			if($('.kw-newsletter-form').length) this.modules.subscribeForm.init();

			if($('.kw-hidden-aside-invoker').length) this.events.hiddenAside();

			if($('.kw-vr-nav-wrap').length) this.modules.verticalNav.init({
				cssPrefix: 'kw-',
				easing: 'easeOutQuint',
				speed: 500
			});

			if($('[data-hidden-container]').length) this.events.hiddenElement();
			if($('[data-hidden-item]').length) this.events.hiddenItem();

			// initialize of synchronized carousels
			if($('.owl-carousel[data-sync]').length) this.templateHelpers.owlSync.init();

			if($('.kw-select-group-container').length) this.events.selectGroup();

		},

		OuterResourcesLoaded: function(){

			if($('.kw-testimonials.kw-testimonials-carousel-v4.owl-carousel').length){
				this.templateHelpers.testimonialsOwlV4();
			}

			// sticky section init
			if($('.kw-sticky').length) this.modules.stickySection.init();
			if($('.kw-isotope').length) this.modules.isotope.init();

			var self = this;
			self.templateHelpers.productRating();

			window.productRating = self.templateHelpers.productRating;

			// init animation for counters
			// if($('.kw-counters-holder').length) this.modules.animatedCounters.init();

			// init animation for progress bars
			if($('.kw-progress-bars-holder').length) this.modules.animatedProgressBars.init({
				speed: 500,
				easing: 'easeOutQuint'
			});

			

		},

		jQueryExtend: function(){

			$.fn.extend({

				kwImagesLoaded : function () {

				    var $imgs = this.find('img[src!=""]');

				    if (!$imgs.length) {return $.Deferred().resolve().promise();}

				    var dfds = [];

				    $imgs.each(function(){
				        var dfd = $.Deferred();
				        dfds.push(dfd);
				        var img = new Image();
				        img.onload = function(){dfd.resolve();};
				        img.onerror = function(){dfd.resolve();};
				        img.src = this.src;
				    });

				    return $.when.apply($,dfds);

				}

			});

		},

		modules: {

			syncOwlCarousel: {

				init: function(){

					this.collection = $('.owl-carousel[data-sync]');
					if(!this.collection.length) return false;

					this.bindEvents();

				},

				bindEvents: function(){

					var self = this;

					this.collection.each(function(i, el){

						var $this = $(el),
							sync = $($this.data('sync'));

						if(!sync.length){
							console.log('Not found carousel with selector ' + $this.data('sync'));
							return;
						}

						// nav
						$this.on('click', '.owl-prev', function(e){
							sync.trigger('prev.owl.carousel');
						});
						$this.on('click', '.owl-next', function(e){
							sync.trigger('next.owl.carousel');
						});

						sync.on('click', '.owl-prev', function(e){
							$this.trigger('prev.owl.carousel');
						});
						sync.on('click', '.owl-next', function(e){
							$this.trigger('next.owl.carousel');
						});

						// // drag 
						$this.on('dragged.owl.carousel', function(e){

					        if(e.relatedTarget.state.direction == 'left'){
					            sync.trigger('next.owl.carousel');
					        }
					        else{
					            sync.trigger('prev.owl.carousel');
					        }
					        
						});

						sync.on('dragged.owl.carousel', function(e){

							if(e.relatedTarget.state.direction == 'left'){
					            $this.trigger('next.owl.carousel');
					        }
					        else{
					            $this.trigger('prev.owl.carousel');
					        }

						});

					});

				}

			},

			verticalNav: {

				baseConfig: {
					cssPrefix: '',
					easing: 'easeOutQuint',
					speed: 500,
					activeClass: 'selected'
				},

				init: function(options){

					this.navigation = $('.kw-vr-nav-wrap');
					if(!this.navigation.length) return;

					var config;

					if(options) config = $.extend({}, this.baseConfig, options);

					this.navigation.data('config', config);

					this._defineHelperProperties();

					this.navigation.find('.kw-sub-menu, .sub-menu').hide();
					this.navigation.on('click.verticalNav', '.kw-has-children a, .menu-item-has-children a', {self: this}, this.handler);


				},

				_defineHelperProperties: function(){

					var _self = this,
						config = _self.navigation.data('config');

					Object.defineProperties(this, {

						cssPrefix: {

							get: function(){

								return config.cssPrefix;

							}

						},

						submenuSelector: {

							get: function(){

								return '.' + this.cssPrefix + 'sub-menu, .sub-menu';

							}

						},

						itemSelector: {

							get: function(){

								return '.' + this.cssPrefix + 'has-children, .menu-item-has-children';

							}

						},

						activeClass: {

							get: function(){

								return this.cssPrefix + config.activeClass;

							}

						},

						easing: {

							get: function(){

								return config.easing;

							}

						},

						speed: {

							get: function(){

								return config.speed;

							}

						}

					});

				},

				handler: function(e){

					var _self = e.data.self,
						$this = $(this),
						$item = $this.parent();

					if(!$this.hasClass('kw-prevented') && $item.hasClass('kw-has-children')){

						$this.addClass('kw-prevented');

						$item
							.addClass(_self.activeClass)
							.children(_self.submenuSelector)
							.stop()
							.slideDown({
								duration: _self.speed,
								easing: _self.easing
							})
							.end()
							.siblings(_self.itemSelector)
							.removeClass(_self.activeClass)
							.children('.kw-prevented')
							.removeClass('kw-prevented')
							.siblings(_self.submenuSelector)
							.stop()
							.slideUp({
								duration: _self.speed,
								easing: _self.easing
							});

						e.preventDefault();

					}

				},

				reset: function(){



				}

			},

			/**
			 * Generates back to top button
			 **/
			backToTop: {

				init: function(config){
					
					var self = this;

					if(config) this.config = $.extend(this.config, config);

					this.btn = $('<button></button>', {
						class: self.config.cssPrefix+'back-to-top animated stealthy',
						html: '<span class="lnr icon-chevron-up"></span>'
					});

					this.bindEvents();

					$('body').append(this.btn);

				},

				config: {
					breakpoint: 700,
					showClass: 'zoomIn',
					hideClass: 'zoomOut',
					easing: 'linear',
					speed: 500,
					cssPrefix: ''
				},

				bindEvents: function(){

					var page = $('html, body'),
						self = this;

					this.btn.on('click', function(e){

						page.stop().animate({

							scrollTop: 0

						}, {
							easing: self.config.easing,
							duration: self.config.speed
						});

					});

					this.btn.on($.knowhere.ANIMATIONEND, function(e){

						e.preventDefault();
						
						var $this = $(this);

						if($this.hasClass(self.config.hideClass)){

							$this
								.addClass('stealthy')
								.removeClass(self.config.hideClass + " " + self.config.cssPrefix + "inview");

						}

					});

					$(window).on('scroll.backtotop', { self: this}, this.toggleBtn);

				},

				toggleBtn: function(e){

					var $this = $(this),
						self = e.data.self;

					if($this.scrollTop() > self.config.breakpoint && !self.btn.hasClass(self.config.cssPrefix + 'inview')){

						self.btn
								.addClass(self.config.cssPrefix + 'inview')
								.removeClass('stealthy');

						if($.knowhere.ANIMATIONSUPPORTED){
							self.btn.addClass(self.config.showClass);
						}

					}
					else if($this.scrollTop() < self.config.breakpoint && self.btn.hasClass(self.config.cssPrefix + 'inview')){

						self.btn.removeClass(self.config.cssPrefix + 'inview');

						if(!$.knowhere.ANIMATIONSUPPORTED){
							self.btn.addClass('stealthy');
						}
						else{
							self.btn.removeClass(self.config.showClass)
									.addClass(self.config.hideClass);
						}

					}

				}

			},

			/**
			 * Contact Form module
			 */
			contactForm: {

				init: function(collection){

					this.collection = collection ? collection : $('.kw-contact-form');
					if(!this.collection.length) return;

					this.initValidator();

				},

				initValidator: function(){

					var _self = this;

					this.collection.each(function(i, el){

						var $this = $(el),
							form = $this.get(0);

						if(!(form instanceof HTMLFormElement) || !window.Validator) return;

						$this.data('validator', new Validator({

							form: form,
							cssPrefix: 'kw-',
							incorrectClass: 'invalid',
							correctClass: 'valid',
							rules: [
								{
									element: form.elements['your-name'],
									name: 'Name',
									rules: {
										empty: null
									}
								},
								{
									element: form.elements['your-email'],
									name: 'Email',
									rules: {
										empty: null,
										pattern: /^(([^<>()\[\]\.,;:\s@\"]+(\.[^<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i
									}
								},
								{
									element: form.elements['your-message'],
									name: 'Message',
									rules: {
										empty: null,
										min: 10
									}
								}
							],
							onIncorrect: function(errorsList){

								$.knowhere.modules.alertMessage({
									element: $this,
									type: 'error',
									message: errorsList
								});

							},
							onCorrect: _self.send

						}));

					});

				},

				send: function(){

					var $this = $(this); // submitted form

					$.ajax({
						type: 'POST',
						url: 'php/contactform_handler.php',
						dataType: 'json',
						data: $this.serialize(),
						success: function(response){

							var alertBoxOptions;

							if(response.status == 'success'){

								alertBoxOptions = {
									element: $this,
									type: 'success',
									message: response.statusText
								};

								$this.find('input:not([type="submit"]), textarea').val('');

							}
							else if(response.status == 'fail'){

								alertBoxOptions = {
									element: $this,
									type: 'error',
									message: response.errors
								};

							}

							$.knowhere.modules.alertMessage(alertBoxOptions);

						},
						error: function(jqXHR, response, errorThrown){

							$.knowhere.modules.alertMessage({
								element: $this,
								type: 'error',
								message: errorThrown
							});

						}

					});

				}

			},

			/**
			 *
			 */
			subscribeForm: {

				init: function(collection){

					this.collection = collection ? collection : $('.kw-newsletter-form');
					if(!this.collection.length) return;

					this.initValidator();

				},

				initValidator: function(){

					var _self = this;

					this.collection.each(function(i, el){

						var $this = $(el),
							form = $this.get(0);

						if(!(form instanceof HTMLFormElement) || !window.Validator) return;

						$this.data('validator', new Validator({

							form: form,
							cssPrefix: 'kw-',
							incorrectClass: 'invalid',
							correctClass: 'valid',
							rules: [
								{
									element: form.elements['email'],
									name: 'Email',
									rules: {
										empty: null,
										pattern: /^(([^<>()\[\]\.,;:\s@\"]+(\.[^<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i
									}
								}
							],
							onIncorrect: function(errorsList){

								$.knowhere.modules.alertMessage({
									element: $this,
									type: 'error',
									message: errorsList
								});

							},
							onCorrect: _self.send

						}));

					});

				},

				send: function(){

					var $this = $(this); // submitted form

					$.ajax({
						type: 'POST',
						url: 'php/subscribeform_handler.php',
						dataType: 'json',
						data: $this.serialize(),
						success: function(response){

							var alertBoxOptions;

							if(response.status == 'success'){

								alertBoxOptions = {
									element: $this,
									type: 'success',
									message: response.statusText
								};

								$this.find('input:not([type="submit"]), textarea').val('');

							}
							else if(response.status == 'fail'){

								alertBoxOptions = {
									element: $this,
									type: 'error',
									message: response.errors
								};

							}

							$.knowhere.modules.alertMessage(alertBoxOptions);

						},
						error: function(jqXHR, response, errorThrown){

							$.knowhere.modules.alertMessage({
								element: $this,
								type: 'error',
								message: errorThrown
							});

						}

					});

				}

			},

			/**
			 * Function to show alert message wherever.
			 * Required: Handlebars
			 * 
			 * @param Object options
			 *
			 * @return jQuery messageBox
			 */
			alertMessage: function(options){

				var data = {
					element: options && options.element || $('body'),
					type: options && options.type || 'intermediate',
					message: options && options.message || ''
				};

				var template = '<div class="kw-alert-{{type}}">\
									<button type="button" class="kw-close"></button>\
									<div class="kw-alert-inner">\
										{{message}}\
									</div>\
								</div>';

				var messageBox = $(Handlebars.compile(template)(data)).hide();

				data.element.append(messageBox);

				return messageBox.slideDown({
					duration: 500,
					easing: 'easeOutQuint'
				});

			},

			/**
			 * Describes the behavior of drop-down lists.
			 */
			dropdown: {

				config: {
					'cssPrefix': '',
					'speed': 1000,
					'animation-in': 'fadeInUp',
					'animation-out': 'fadeOutDown'
				},

				init: function(options){

					var self = this;

					if(options) $.extend(this.config, options);

					// Auxiliary properties

					Object.defineProperties(this, {

						invoker: {

							get: function(){

								return '.' + this.config.cssPrefix + 'dropdown-invoker';

							}

						},

						dropdown: {

							get: function(){

								return '.' + this.config.cssPrefix + 'dropdown-list';

							}

						},

						container: {

							get: function(){

								return '.' + this.config.cssPrefix + 'dropdown';

							}

						},

						activeClass: {

							get: function(){

								return this.config.cssPrefix + 'opened';

							}

						}

					});

					$('body').on('click.dropdown', this.invoker, { self: this }, this.handler);
					$(document).on('click.dropdown', function(e){

						e.stopPropagation();
						if(!$(e.target).closest(self.container).length) self.close($('body').find(self.dropdown));

					});

				},

				handler: function(e){

					var $this = $(this),
						self = e.data.self,
						dropdown = $this.siblings(self.dropdown),
						container = $this.closest(self.container);

					if(dropdown.length){

						if(!dropdown.data('initialized')) self.initDropdown(dropdown);

						if(!container.hasClass(self.activeClass)){

							container.addClass(self.activeClass);
							dropdown.addClass(self.config['animation-in']);

						}
						else{

							if(!dropdown.data('timeOutId')){

								self.close(dropdown);

							}


						}

					}

					e.stopPropagation();
					e.preventDefault();

				},

				close: function(dropdown){

					var self = this,
						container = dropdown.closest(this.container);

					dropdown
						.removeClass(self.config['animation-in'])
						.addClass(self.config['animation-out'])
						.data('timeOutId', setTimeout(function(){

							container.removeClass(self.activeClass);
							dropdown
								.removeClass(self.config['animation-out'])
								.data('timeOutId', false);

						}, self.config.speed));

				},

				initDropdown: function(dropdown){

					dropdown
						.addClass('animated')
						.attr('style', 'animation-duration: ' + this.config['speed'] + 'ms')
						.data('initialized', true);

				}

			},

			/**
			 * Describes the loading of the modal windows.
			 */
			modalWindows: {

				init: function(){

					var $body = $('body');

					$body.on('click.arcticmodal', '[data-modal]', function(e){

						var $this = $(this),
							path = $this.data('modal');

						if(path){

							$.arcticmodal({
								type: 'ajax',
								url: path,
								speed: 350,
								ajax: {
							        type: 'POST',
							        cache: false
							    },
								afterClose: function(){

									setTimeout(function(){

										if(!$body.find('.arcticmodal-container').length){

											$body.css({
												'overflow-x': 'hidden',
												'overflow-y': 'visible'
											});

										}

									}, 0);

								}
							});

						}

						e.preventDefault();
						e.stopPropagation();

					});

				}

			},

			/**
			 * Initialize global close event
			 * @return Object Core;
			 **/
			closeBtn: function(){

				$('body').on('click.globalclose', '.kw-close:not(.kw-shopping-cart-full .kw-close)', function(e){

					e.preventDefault();

					$(this).parent().stop().animate({
						opacity: 0
					}, function(){

						$(this).stop().slideUp(function(){

							$(this).remove();

						});

					});

				});

				return this;

			},

			removeProduct: function(collection){

				var c = collection ? collection : $('.kw-shopping-cart-full');

				c.on('click.removeProduct', '.kw-close', function(e){

					e.preventDefault();

					$(this).closest('tr').stop().fadeOut(function(){
						$(this).remove();
					});

				});

			},

			/**
			 * Sticky header section
			 **/
			stickySection: {

				STICKYPADDING: 10,
				MAXSTICKYHEIGHT: 90,

				init: function(){

					this.body = $('body');
					this.sticky = $('#header').find('.kw-sticky');

					if(!this.sticky.length) return;

					this.bindEvents();
					this.updateDocumentState();

				},

				updateDocumentState: function(){
					
					var self = this;

					if(self.resizeTimeoutId) clearTimeout(self.resizeTimeoutId);

					self.resizeTimeoutId = setTimeout(function(){

						self.reset();

						self.sticky.removeAttr('style');

						if($(window).width() < 768) return;

						self.stickyHeight = self.sticky.outerHeight();

						if(self.stickyHeight > self.MAXSTICKYHEIGHT){

							self.needScale = true;

							self.defPaddingTop = parseInt(self.sticky.css('padding-top'), 10);
							self.defPaddingBottom = parseInt(self.sticky.css('padding-bottom'), 10);

							self.stickyOffset = self.sticky.offset().top + self.defPaddingTop - self.STICKYPADDING;

						}
						else{

							self.needScale = false;
							self.stickyOffset = self.sticky.offset().top;

						}					

						$(window).trigger('scroll.sticky');

					}, 120);

				},

				reset: function(){

					var $w = $(window);

					this.sticky.removeClass('kw-sticked');

					this.freeSpace();

					if($w.width() < 768 && this.hasEvents){

						var spacer = this.sticky.siblings('.kw-sticky-spacer');
						if(spacer.length) spacer.remove();

						$w.off('scroll.sticky');
						this.hasEvents = false;

						return;

					}
					else if($w.width() >= 768 && !this.hasEvents){

						$w.on('scroll.sticky', {self: this}, this.scrollHandler);
						this.hasEvents = true;

					}

				},

				bindEvents: function(){

					var $w = $(window),
						self = this;

					$w.on('scroll.sticky', {self: this}, this.scrollHandler);
					$w.on('resize.sticky', function(){

						self.updateDocumentState();

					});
					self.hasEvents = true;

				},

				scrollHandler: function(e){

					var $w = $(this),
						self = e.data.self;

					if($w.scrollTop() > self.stickyOffset && !self.sticky.hasClass('kw-sticked')){

						self.sticky.addClass('kw-sticked');

						if(self.needScale){

							self.sticky.css({
								'padding-top': self.STICKYPADDING,
								'padding-bottom': self.STICKYPADDING
							});

						}

						self.fillSpace();

					}
					else if($w.scrollTop() <= self.stickyOffset && self.sticky.hasClass('kw-sticked')){

						self.sticky.removeClass('kw-sticked');

						if(self.needScale){
						
							self.sticky.css({
								'padding-top': self.defPaddingTop,
								'padding-bottom': self.defPaddingBottom
							});

						}

						self.freeSpace();

					}

				},

				fillSpace: function(){

					var self = this,
						parent = self.sticky.parent(),
						spacer = parent.children('.kw-sticky-spacer');

					if(spacer.length){
						spacer.show().css('height', self.stickyHeight);
						return false;
					}
					else{

						spacer = $('<div></div>', {
							class: 'kw-sticky-spacer',
							style: 'height:' + self.stickyHeight + 'px'
						});

						self.sticky.before(spacer);

					}

				},

				freeSpace: function(){

					var self = this,
						parent = self.sticky.parent(),
						spacer = parent.children('.kw-sticky-spacer');

					if(spacer.length) spacer.hide();

				}

			},

			animatedProgressBars: {

				init: function(config){

					this.collection = $('.kw-pbar');
					if(!this.collection.length) return;

					this.holdersCollection = $('.kw-progress-bars-holder');
					this.w = $(window);

					this.preparePBars();

					$.extend(this.config, config);

					this.updateDocumentState();

					this.w.on('resize.animatedprogressbars', this.updateDocumentState.bind(this));

					this.w.on('scroll.animatedprogressbars', {self: this}, this.scrollHandler);

					this.w.trigger('scroll.animatedprogressbars');

				},

				config: {
					speed: $.fx.speed,
					easing: 'linear'
				},

				updateDocumentState: function(){

					this.breakpoint = this.w.height() / 1.4;

				},

				preparePBars: function(){

					this.collection.each(function(i, el){

						var $this = $(el),
							indicator = $this.children('.kw-pbar-inner'),
							value = $this.data('value');

						$this.add(indicator).data('r-value', value);
						$this.add(indicator).attr('data-value', 0);

						indicator.css('width', 0);

					});

				},

				scrollHandler: function(e){

					var self = e.data.self;

					self.holdersCollection.each(function(i, el){

						var holder = $(el);

						if(self.w.scrollTop() + self.breakpoint >= holder.offset().top && !holder.hasClass('kw-animated')){

							self.animateAllBarsIn(holder);
							holder.addClass('kw-animated');

							if(i === self.holdersCollection.length - 1) self.destroy();

						}

					});


				},

				animateAllBarsIn: function(holder){

					var self = this,
						pbarsCollection = holder.find('.kw-pbar');

					pbarsCollection.each(function(i, el){

						var pbar = $(el),
							indicator = pbar.children('.kw-pbar-inner'),
							value = pbar.data('r-value'),
							pbarWidth = pbar.outerWidth();

						indicator.stop().animate({
							width: value + '%'
						}, {
							duration: self.config.speed,
							easing: self.config.easing,
							step: function(now){
								pbar.add(indicator).attr('data-value', Math.round(now));
							}
						});

					});

				},

				destroy: function(){

					this.w.off('scroll.animatedprogressbars');

				}

			},	

			animatedCounters: {

				init: function(){

					this.collection = $('.kw-counter');
					if(!this.collection.length) return;

					this.w = $(window);

					this.prepareCounters();
					this.updateDocumentState();

					this.w.on('scroll.animatedcounter', {self: this}, this.scrollHandler);
					this.w.on('resize.animatedcounter', this.updateDocumentState.bind(this));

					this.w.trigger('scroll.animatedcounter');

				},

				updateDocumentState: function(){

					this.breakpoint = this.w.height() / 1.4;

				},

				prepareCounters: function(){

					this.collection.each(function(i, el){

						var $this = $(el),
							value = $this.data('value');

						$this.data('r-value', value);
						$this.attr('data-value', 0);
						$this.find('.kw-counter-value').text(0)

					});

				},

				scrollHandler: function(e){

					var self = e.data.self;

					self.collection.each(function(i, el){

						var counter = $(el);

						if(self.w.scrollTop() + self.breakpoint > counter.offset().top && !counter.hasClass('nv-animated')){

							counter.addClass('nv-animated');
							self.animateCounter(counter);

							if(i === self.collection.length - 1) self.destroy();

						}

					});

				},

				animateCounter: function(counter){

					var value = counter.data('r-value'),
						intId, currentValue = 0;

					intId = setInterval(function(){

						counter.attr('data-value', currentValue+=19);
						counter.find('.kw-counter-value').text(currentValue+=19);

						if(currentValue >= value){
							counter.attr('data-value', value);
							counter.find('.kw-counter-value').text(value);
							clearInterval(intId);
						}

					}, 4);

				},

				destroy: function(){

					this.w.off('scroll.animatedcounter');
					this.w.off('resize.animatedcounter');

				}

			},

			isotope: {

				baseConfig: {
					itemSelector: '.kw-entry-wrap, .kw-advertising-wrap, .kw-listing-item-wrap',
					percentPosition: true,
					transitionDuration: '0.5s'
				},

				init: function(){

					this.collection = $('.kw-isotope');
					if(!this.collection.length) return;

					if(window.navigator.userAgent.toLowerCase().indexOf('android') !== -1) this.collection.addClass('kw-android');

					$.extend(this.baseConfig, {
						isOriginLeft: !$.knowhere.ISRTL
					});

					this.run();

				},

				run: function(){

					var self = this;

					this.collection.each(function(i, el){

						var container = $(el),
							config = $.extend({
								layoutMode: container.data('masonry') ? 'masonry' : 'fitRows'
							}, self.baseConfig);

						if(container.data('filter')){

							self.initFilter(container);

						}

						if(container.data('load-more-element')){

							self.initLoadMore(container);

						}

						container.kwImagesLoaded().then(function(){

							container.isotope(config);

						});

					});

				},

				initFilter: function(isotope){

					var filterElement = $(isotope.data('filter'));

					if(!filterElement.length) return;

					filterElement.on('click.filter', '[data-filter]', function(e){

						e.preventDefault();

						var $this = $(this);

						$this
							.addClass('kw-active')
							.siblings()
							.removeClass('kw-active');

						isotope.isotope({filter: $this.data('filter')});

					});

				}

			},

			googleMaps: function(){

				if(!$('.kw-gmap').length) return;

				var mapsCollection = [],
					mapSettings = {

					map_options: {
						zoom: 15,
						scrollwheel: false
					},

					locations: [
						{
							lat: 40.710542,
							lon: -74.008627,
							icon: 'images/marker_8.png',
							title: 'Main office'
						}
					],

					generate_controls: false,
					controls_on_map: false,
					view_all: false

				},

				mapStyles = {

					'satellite' : {
						map_options: {
							zoom: 18,
							scrollwheel: false,
							mapTypeId: google.maps.MapTypeId.SATELLITE
						}
					},

					'grayscale' : {
						map_options:{
							zoom: 16,
							scrollwheel: false
						},
						styles:{
							'grayscale': [{
						        "featureType": "water",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#e9e9e9"
						            },
						            {
						                "lightness": 17
						            }
						        ]
						    },
						    {
						        "featureType": "landscape",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#f5f5f5"
						            },
						            {
						                "lightness": 20
						            }
						        ]
						    },
						    {
						        "featureType": "road.highway",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#ffffff"
						            },
						            {
						                "lightness": 17
						            }
						        ]
						    },
						    {
						        "featureType": "road.highway",
						        "elementType": "geometry.stroke",
						        "stylers": [
						            {
						                "color": "#ffffff"
						            },
						            {
						                "lightness": 29
						            },
						            {
						                "weight": 0.2
						            }
						        ]
						    },
						    {
						        "featureType": "road.arterial",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#ffffff"
						            },
						            {
						                "lightness": 18
						            }
						        ]
						    },
						    {
						        "featureType": "road.local",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#ffffff"
						            },
						            {
						                "lightness": 16
						            }
						        ]
						    },
						    {
						        "featureType": "poi",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#f5f5f5"
						            },
						            {
						                "lightness": 21
						            }
						        ]
						    },
						    {
						        "featureType": "poi.park",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#dedede"
						            },
						            {
						                "lightness": 21
						            }
						        ]
						    },
						    {
						        "elementType": "labels.text.stroke",
						        "stylers": [
						            {
						                "visibility": "on"
						            },
						            {
						                "color": "#ffffff"
						            },
						            {
						                "lightness": 16
						            }
						        ]
						    },
						    {
						        "elementType": "labels.text.fill",
						        "stylers": [
						            {
						                "saturation": 36
						            },
						            {
						                "color": "#333333"
						            },
						            {
						                "lightness": 40
						            }
						        ]
						    },
						    {
						        "elementType": "labels.icon",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "transit",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#f2f2f2"
						            },
						            {
						                "lightness": 19
						            }
						        ]
						    },
						    {
						        "featureType": "administrative",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#fefefe"
						            },
						            {
						                "lightness": 20
						            }
						        ]
						    },
						    {
						        "featureType": "administrative",
						        "elementType": "geometry.stroke",
						        "stylers": [
						            {
						                "color": "#fefefe"
						            },
						            {
						                "lightness": 17
						            },
						            {
						                "weight": 1.2
						            }
						        ]
						    }]
						}
					},

					'clean_cut' : {
						styles: {
							'clean_cut': [ {
						        "featureType": "road",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "lightness": 100
						            },
						            {
						                "visibility": "simplified"
						            }
						        ]
						    },
						    {
						        "featureType": "water",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "visibility": "on"
						            },
						            {
						                "color": "#C6E2FF"
						            }
						        ]
						    },
						    {
						        "featureType": "poi",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#C5E3BF"
						            }
						        ]
						    },
						    {
						        "featureType": "road",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#D1D1B8"
						            }
						        ]
						    }]
						}
					},
					'AppleMaps-esque': {
						map_options:{
							zoom: 14,
							scrollwheel: false
						},
						styles: {
							'AppleMaps-esque': [
							    {
							        "featureType": "landscape.man_made",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "color": "#f7f1df"
							            }
							        ]
							    },
							    {
							        "featureType": "landscape.natural",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "color": "#d0e3b4"
							            }
							        ]
							    },
							    {
							        "featureType": "landscape.natural.terrain",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "visibility": "off"
							            }
							        ]
							    },
							    {
							        "featureType": "poi",
							        "elementType": "labels",
							        "stylers": [
							            {
							                "visibility": "off"
							            }
							        ]
							    },
							    {
							        "featureType": "poi.business",
							        "elementType": "all",
							        "stylers": [
							            {
							                "visibility": "off"
							            }
							        ]
							    },
							    {
							        "featureType": "poi.medical",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "color": "#fbd3da"
							            }
							        ]
							    },
							    {
							        "featureType": "poi.park",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "color": "#bde6ab"
							            }
							        ]
							    },
							    {
							        "featureType": "road",
							        "elementType": "geometry.stroke",
							        "stylers": [
							            {
							                "visibility": "off"
							            }
							        ]
							    },
							    {
							        "featureType": "road",
							        "elementType": "labels",
							        "stylers": [
							            {
							                "visibility": "off"
							            }
							        ]
							    },
							    {
							        "featureType": "road.highway",
							        "elementType": "geometry.fill",
							        "stylers": [
							            {
							                "color": "#ffe15f"
							            }
							        ]
							    },
							    {
							        "featureType": "road.highway",
							        "elementType": "geometry.stroke",
							        "stylers": [
							            {
							                "color": "#efd151"
							            }
							        ]
							    },
							    {
							        "featureType": "road.arterial",
							        "elementType": "geometry.fill",
							        "stylers": [
							            {
							                "color": "#ffffff"
							            }
							        ]
							    },
							    {
							        "featureType": "road.local",
							        "elementType": "geometry.fill",
							        "stylers": [
							            {
							                "color": "black"
							            }
							        ]
							    },
							    {
							        "featureType": "transit.station.airport",
							        "elementType": "geometry.fill",
							        "stylers": [
							            {
							                "color": "#cfb2db"
							            }
							        ]
							    },
							    {
							        "featureType": "water",
							        "elementType": "geometry",
							        "stylers": [
							            {
							                "color": "#a2daf2"
							            }
							        ]
							    }
							]
						}
					} 
				};

				$('.kw-gmap').each(function(i, el){

					var map = $.extend(mapSettings, mapStyles[$(el).data('gmap-type')]);

					if($(el).data('locations')){

						map.locations = $(el).data('locations');

					}

					map.map_div = '#' + $(el).attr('id');



					mapsCollection.push(new Maplace(map).Load());

				});

				if(!mapsCollection.length) return;

				$(window).on('resize.map', function(){

				 	setTimeout(function(){

					 	mapsCollection.forEach(function(elem, index, arr){

					 		elem.Load();

					 	});

					 }, 100);

	            });

			},

			JobManager: {

				baseMapConfig: {
					map_options: {
						zoom: 15,
						scrollwheel: false
					},
					styles: {
						'AppleMaps-esque': [
						    {
						        "featureType": "landscape.man_made",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#f7f1df"
						            }
						        ]
						    },
						    {
						        "featureType": "landscape.natural",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#d0e3b4"
						            }
						        ]
						    },
						    {
						        "featureType": "landscape.natural.terrain",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "poi",
						        "elementType": "labels",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "poi.business",
						        "elementType": "all",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "poi.medical",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#fbd3da"
						            }
						        ]
						    },
						    {
						        "featureType": "poi.park",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#bde6ab"
						            }
						        ]
						    },
						    {
						        "featureType": "road",
						        "elementType": "geometry.stroke",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "road",
						        "elementType": "labels",
						        "stylers": [
						            {
						                "visibility": "off"
						            }
						        ]
						    },
						    {
						        "featureType": "road.highway",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#ffe15f"
						            }
						        ]
						    },
						    {
						        "featureType": "road.highway",
						        "elementType": "geometry.stroke",
						        "stylers": [
						            {
						                "color": "#efd151"
						            }
						        ]
						    },
						    {
						        "featureType": "road.arterial",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#ffffff"
						            }
						        ]
						    },
						    {
						        "featureType": "road.local",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "black"
						            }
						        ]
						    },
						    {
						        "featureType": "transit.station.airport",
						        "elementType": "geometry.fill",
						        "stylers": [
						            {
						                "color": "#cfb2db"
						            }
						        ]
						    },
						    {
						        "featureType": "water",
						        "elementType": "geometry",
						        "stylers": [
						            {
						                "color": "#a2daf2"
						            }
						        ]
						    }
						]
					},
					map_div: '#kw-listings-gmap',
					generate_controls: false,
					controls_on_map: false,
					view_all: false
				},

				init: function(){

					this.map = $('.kw-listings-gmap');
					this.controls = $('.kw-listing-layout-control');
					this.loadMore = $('.kw-listings-load-more');

					if(this.map.length) this.initMapModule();
					if(this.controls.length) this.initLayoutModule();
					if(this.loadMore.length) this.initLoadMoreModule();

				},

				initMapModule: function(){

					this.itemsCollection = $('.kw-listings .kw-listing-item');


					if(this.itemsCollection.length) {

						this.baseMapConfig.locations = [];
						this.fillLocations();

					}

					this.initMap($.extend(this.baseMapConfig, {

					}));

				},

				initMap: function(config){

					var self = this;

					this.mapPlace = new Maplace(config);
					this.mapPlace.Load();

					$(window).on('resize.listing-gmap', function(){

						if(self.timeOutId) clearTimeout(self.timeOutId);

						self.timeOutId = setTimeout(function(){

						 	self.mapPlace.Load();

						 }, 100);

					});

				},

				fillLocations: function(){

					var _self = this;

					this.itemsCollection.each(function(i, el){

						var $this = $(el);

						_self.baseMapConfig.locations.push({
							lat: $this.data('latitude'),
							lon: $this.data('longitude'),
							icon: $this.data('marker')
						});

					});

				},

				initLayoutModule: function(){

					this.controls.on('click', { self: this }, this.changeLayout);

				},

				changeLayout: function(e){

					console.log(123);

					var $this = $(this),
						container = $($this.data('container')),
						items = container.find('.kw-listing-item');

					if(!items.length) return false;

					$this
						.addClass('kw-active')
						.siblings('.kw-listing-layout-control')
						.removeClass('kw-active');

					container.removeClass('kw-grid-view kw-list-view').addClass('kw-' + $this.data('layout') + '-view');

					if($this.data('columns')) container.removeClass('kw-cols-2 kw-cols-3 kw-cols-4').addClass('kw-cols-' + $this.data('columns'));

					if(container.hasClass('kw-isotope')) container.isotope('layout');


					e.preventDefault();
					return false;

				},

				initLoadMoreModule: function(){

					var self = this;

					this.loadMore.on('click.job_listings-load-more', function(e){

						var $this = $(this),
							container = $($(this).data('container')),
							maxItems = container.data('max-items');

						console.log(maxItems);

						if(!container.length) return;

						$this.addClass('kw-loading');

						$.ajax({
							type: 'GET',
							url: 'json/demo_data.json',
							dataType: 'json',
							success: function(data){

								
								self.insertNewItems(container, data.items);

								$this.removeClass('kw-loading');

								if(container.find('.kw-listing-item').length >= maxItems){

									$this.stop().slideUp({
										duration: 500,
										easing: 'easeOutQuint',
										complete: function(){

											$(this).add($(this).parent('[class*="align-"]')).remove();

										}
									});

								}

							},
							error: function(data){

								$this.removeClass('kw-loading');

							}
						});

						e.preventDefault();

					});

				},

				insertNewItems: function(container, items){

					var self = this,
						ratingCollection = $(),
						type;

					if(!container.length) return;


					if(container.hasClass('kw-type-1')) type = 'type-1';
					if(container.hasClass('kw-type-2')) type = 'type-2';


					$.each(items, function(i, el){

						var $item = $(Handlebars.compile(self.itemTemplate[type])(el)),
							rating = $item.find('.kw-rating');

						container.append($item);

						if(container.hasClass('kw-isotope')) {
							container
								.isotope('appended', container.children().not('[style]'))
								.isotope('layout');
						}

						if(rating.length) ratingCollection = ratingCollection.add(rating);

						if(self.mapPlace) {

						self.mapPlace.AddLocation({
							lat: el.latitude,
							lon: el.longitude,
							icon: el.marker,
							title: el.title
						},0, true);

						}

					});

					$.knowhere.templateHelpers.productRating(ratingCollection);

				},


				itemTemplate: {
					'type-1': '<div class="kw-listing-item-wrap">\
								<article class="kw-listing-item" data-latitude="{{latitude}}" data-longitude="{{longitude}}" data-marker="{{marker}}">\
									<div class="kw-listing-item-media">\
										<a href="{{link}}" class="kw-listing-item-thumbnail">\
											<img src="{{thumbnail}}" alt="{{title}}">\
										</a>\
										<span class="kw-listing-item-icon">\
											<span class="lnr icon-dinner"></span>\
										</span>\
										<a href="#" class="kw-listing-item-like">\
											<span class="lnr icon-heart"></span>\
										</a>\
									</div>\
									<div class="kw-listing-item-info">\
										<header class="kw-listing-item-header">\
											<h3 class="kw-listing-item-title"><a href="{{link}}">{{title}}</a></h3>\
											<div class="kw-sm-table-row kw-xs-small-offset">\
												<div class="col-xs-6">\
													<div class="kw-listing-item-rating kw-rating" data-rating="{{rating}}"></div>\
												</div>\
											</div>\
										</header>\
										<ul class="kw-listing-item-data kw-icons-list">\
											<li class="kw-listing-item-location"><span class="lnr icon-map-marker"></span>{{location}}</li>\
											<li class="kw-listing-item-phone"><span class="lnr icon-telephone"></span>{{phone}}</li>\
										</ul>\
										<a href="#" class="kw-listing-item-pintpoint"><span class="lnr icon-pushpin"></span> Pintpoint</a>\
									</div>\
								</article>\
							</div>',
					'type-2': '<div class="kw-listing-item-wrap">\
							<article class="kw-listing-item" data-latitude="{{latitude}}" data-longitude="{{longitude}}" data-marker="{{marker}}">\
								<div class="kw-listing-item-media">\
									<a href="{{link}}" class="kw-listing-item-thumbnail">\
										<img src="{{thumbnail}}" alt="{{title}}">\
									</a>\
								</div>\
								<span class="kw-listing-item-icon">\
									<span class="lnr icon-dinner"></span>\
								</span>\
								<a href="#" class="kw-listing-item-like">\
									<span class="lnr icon-heart"></span>\
								</a>\
								<div class="kw-listing-item-info">\
									<header class="kw-listing-item-header">\
										<h3 class="kw-listing-item-title"><a href="{{link}}">{{title}}</a></h3>\
										<div class="kw-sm-table-row kw-xs-small-offset">\
											<div class="col-xs-6">\
												<div class="kw-listing-item-rating kw-rating" data-rating="{{rating}}"></div>\
											</div>\
										</div>\
									</header>\
									<ul class="kw-listing-item-data kw-icons-list">\
										<li class="kw-listing-item-location"><span class="lnr icon-map-marker"></span>{{location}}</li>\
									</ul>\
								</div>\
							</article>\
						</div>'

				} 

			}

		},

		events: {

			selectGroup: function() {

				var container = $('.kw-select-group-container'),
					group = container.find('.kw-select-group-inner'),
					defaultIcon = container.find('.kw-select-group-icon-default'),
					activeIcon = container.find('.kw-select-group-icon-active');


				if(!container.length || !group.length) return;

				group.on('click', function(e){

					e.stopPropagation();

				});

				container.on('click', function(e){

					$(this).toggleClass('kw-active');

					group.slideToggle();

				});

			},

			fileInputField: function() {

				$('body').on('click.fileinput', '.kw-file-input-field', function(e){

					var input = $($(this).data('input-field'));

					if(!input.length) return;

					input.click();

					e.preventDefault();

				});

			},

			hiddenAside: function(){

				var aside = $('#hidden-aside'),
					page = $('.kw-wide-layout-type');
				if(!aside.length || !page.length) return;



				$('body').on('click.hiddenAside', '.kw-hidden-aside-invoker', function(e){

					aside.add(page).addClass('kw-moved');

					e.preventDefault();

				});

				$('body').on('click.hiddenAside', '.kw-hidden-aside-close', function(e){

					aside.add(page).removeClass('kw-moved');

					e.preventDefault();

				});

			},

			hiddenElement: function() {

				var $body = $('body');

				$body.on('click.hiddenElement','[data-hidden-container]', function(e){

					var $this = $(this),
						$container = $($this.data('hidden-container'));

					if(!$container.length) return;

					var animateIn = $container.data('animate-in') ? $container.data('animate-in') : 'fadeInDown',
						animateOut = $container.data('animate-out') ? $container.data('animate-out') : 'fadeOutDown';

					// init
					if(!$container.hasClass('animated')) {
						$container.addClass('animated');
						$container.on($.knowhere.ANIMATIONEND, function(e){

							if($container.hasClass(animateOut)) {
								$container.removeClass(animateOut + ' kw-visible');
								$body.removeClass('kw-locked-by-hidden-element');
							}

						});
					}

					if($container.hasClass(animateIn)) {
						$container.removeClass(animateIn).addClass(animateOut);
						return;
					}

					
					$container.removeClass(animateOut).addClass(animateIn + ' kw-visible');
					$body.addClass('kw-locked-by-hidden-element');
					


					e.preventDefault();

				});

			},

			hiddenItem: function() {

				$('body').on('click.hiddenItem', '[data-hidden-item]', function(e){

					var $this = $(this),
						$item = $($this.data('hidden-item'));

					if(!$item.length) return;

					$this.toggleClass('kw-active');
					$item.slideToggle({
						duration: $.knowhere.TRANSITIONDURATION,
						easeing: 'easeOutQuint'
					});

					e.preventDefault();

				});

			}

		},

		templateHelpers: {

			owlSync: {

				init: function(){

					this.collection = $('.owl-carousel[data-sync]');
					if(!this.collection.length) return;

					this.prepare();

				},

				prepare: function(){

					this.collection.each(function(i, el){

						var $this = $(el),
							sync = $($this.data('sync'));

						sync.on('changed.owl.carousel', function(e){

							var index = e.item.index,
								$thumb = $this.find('.owl-item').eq(index).find('.kw-slideshow-thumb');

							if(!sync.data('afterClicked')) $this.trigger('to.owl.carousel', [index, 350, true]);

							sync.data('afterClicked', false);

							if($thumb.length) {
								
								$thumb.addClass('kw-active')
								.closest('.owl-item')
								.siblings()
								.find('.kw-slideshow-thumb')
								.removeClass('kw-active');

							}



						});

						$this.on('prev.owl.carousel', function(){

							sync.trigger('prev.owl.carousel');

						});

						$this.on('next.owl.carousel', function(){

							sync.trigger('next.owl.carousel');

						});

						$this.on('click.owlSync', '.owl-item', function(e){

							e.preventDefault();

							var index = $(this).index(),
								thumb = $(this).find('.kw-slideshow-thumb');

							if(thumb.length) {

								thumb
									.addClass('kw-active')
									.closest('.owl-item')
									.siblings()
									.find('.kw-slideshow-thumb')
									.removeClass('kw-active');

							}

							sync.data('afterClicked', true);

							sync.trigger('to.owl.carousel', [index, 350, true]);

						});

					});

				}

			},

			/**
			 * Dynamically set background image
			 * @return jQuery collection;
			 **/
			bgImage: function(collection){

				collection = collection ? collection : $('[data-bg]');
				if(!collection.length) return;

				collection.each(function(i, el){

					var $this = $(el),
						imageSrc = $this.data('bg');

					if(imageSrc) $this.css('background-image', 'url('+imageSrc+')');

				});

				return collection;

			},

			testimonialsOwlV4: function(collection){

				collection = collection ? collection : $('.kw-testimonials.kw-testimonials-carousel-v4.owl-carousel');
				if(!collection.length) return;

				collection.each(function(i, el){

					var $this = $(el),
						$dots = $this.find('.owl-dot');

					$this.find('.kw-testimonial').each(function(i, el){

						var authorBox = $(this).find('.kw-author-box');

						$dots.eq(i).append(authorBox);

					});


				});

			},

			fwSectionBg: {

				init: function(){

					var self = this;

					this.collection = $('.kw-section.kw-fw-bg');
					if(!this.collection.length) return;

					this.container = $('.container');
					this.w = $('[class*="-layout-type"]');

					this.render();

					$(window).on('resize.fwSection', function(){

						if(self.timer) clearTimeout(self.timer);

						self.timer = setTimeout(function(){

							self.render();

						}, 50);

					});

				},

				reset: function(){

					if(!this.collection) return;

					var bgElement = this.collection.find('.kw-bg-element');

					bgElement.css({
						'margin-left':'auto',
						'margin-right': 'auto'
					});

					this.render();

				},

				render: function(){

					var self = this;

					this.collection.each(function(i, el){

						var $this = $(el),
							out = Math.abs(self.w.offset().left - $this.offset().left) * -1,
							bgImage = $this.data('fw-bg'),
							bgElement = $this.find('.kw-bg-element');

						if(!bgElement.length){

							bgElement = $('<div></div>', {
								class: 'kw-bg-element'
							});

							if(bgImage) bgElement.css('background-image', 'url(' +bgImage+ ')');

							$this.prepend(bgElement);

						};

						bgElement.css({
							'margin-left': out,
							'margin-right': out
						});

					});

				}

			},

			fwSection: {

				init: function(){

					var self = this;

					this.collection = $('.kw-section.kw-fw');
					if(!this.collection.length) return;

					this.container = $('.container');
					this.w = $('[class*="-layout-type"]');

					this.render();

					$(window).on('resize.fwSection', function(){

						if(self.timer) clearTimeout(self.timer);

						self.timer = setTimeout(function(){

							self.reset();

						}, 50);

					});

				},

				reset: function(){

					if(!this.collection) return;

					this.collection.css({
						'margin-left': 0,
						'margin-right': 0
					});

					this.render();

				},

				render: function(){

					var self = this;

					this.collection.each(function(i, el){

						var $this = $(el),
							out = Math.abs(self.w.offset().left - $this.offset().left) * -1

						$this.css({
							'margin-left': out,
							'margin-right': out
						});

						var isotope = $this.find('.kw-isotope-container');
						if(isotope.length) isotope.isotope('layout');

					});

				}

			},

			/**
			 * Sets correct inner offsets in page header (only for fixed header types)
			 * @return undefined;
			 **/
			pageHeader: {

				init: function(){

					var header = $('#header'),
						pageHeader = $('.kw-page-header').not('.kw-type-4'),
						$w = $(window);

					function correctPosition(){

						if($w.width() < 768) return false;

						var hHeight = header.outerHeight();
						
						pageHeader.add(pageHeader.find('.kw-page-header-media')).css({
							'border-top-width': hHeight,
							'margin-top': hHeight * -1
						});

					}

					correctPosition();
					$(window).on('resize.pageHeader', correctPosition);

				}

			},

			owlHelper: {

				baseConfig: {
					items: 1,
					loop: true,
					nav: true,
					navElement: "button",
					dots: false,
					navText: [],
					rtl: getComputedStyle(document.body).direction === 'rtl',
					autoplay: true,
					autoplayTimeout: 4000,
					autoplayHoverPause: true,
					smartSpeed: 350,
					autoplaySpeed: 350,
					navSpeed: 350,
					dotsSpeed: 350,
					animateIn: false,
					animateOut: false
				},

				init: function(collection){

					collection = collection ? collection : $('.owl-carousel');
					if(!collection.length) return;

					collection.addClass('kw-loading');

					this.adaptive(collection);

				},

				adaptive: function(collection){

					var self = this;

					collection.kwImagesLoaded().then(function(){

						collection.each(function(i, el){

							var $this = $(el);

							var owlData = $this.data('owl.carousel');

							if(owlData){

								if(owlData.settings.dots){

									$this.addClass('owl-dotted');

								}

							}

							$this.on('resized.owl.carousel', function(e){

								self.containerHeight($this);

							});

							$this.on('changed.owl.carousel', function(e){

								self.containerHeight($this);

							});

							self.containerHeight($this);
							$this.removeClass('kw-loading');

						});

					});

				},

				containerHeight: function(owl){

					var _this = this;

					setTimeout(function(){

						var max = 0,
							items = owl.find('.owl-item'),
							activeItems = items.filter('.active').children();

						items.children().css('height', 'auto');

						activeItems.each(function(i, el){

							var $this = $(el),
								height = $this.outerHeight();

							if(height > max) max = height;

						});

						owl.find('.owl-stage-outer:first').stop().animate({
							height: max
						}, {
							duration: 150,
							complete: function(){

								var isotopeContainer = owl.closest('.kw-isotope');
								var owlContainer = owl.closest('.owl-carousel');


								if(isotopeContainer.length) isotopeContainer.isotope('layout');	
								if(owlContainer.length) _this.containerHeight(owlContainer);

							}
						});

					}, 20);

				}

			},

			/**
				** product raring
				**/
				productRating : function(collection){

					var $ratings = collection ? collection : $('.kw-rating').not('.owl-carousel .kw-rating');

					$ratings.each(function(){

						$(this).append("<div class='kw-empty-state'><i class='kw-icon-star-empty'></i><i class='kw-icon-star-empty'></i><i class='kw-icon-star-empty'></i><i class='kw-icon-star-empty'></i><i class='kw-icon-star-empty'></i></div><div class='kw-fill-state'><i class='kw-icon-star'></i><i class='kw-icon-star'></i><i class='kw-icon-star'></i><i class='kw-icon-star'></i><i class='kw-icon-star'></i></div>");

						var $this = $(this),
							rating = $this.data("rating"),
							fillState = $this.children('.kw-fill-state'),
							w = $this.outerWidth();

						fillState.css('width', Math.floor(rating / 5 * w));

					});

				},

		}

	};

	$.knowhere.jQueryExtend();

	$(function(){

		$.knowhere.DOMReady();

	});

	$(window).on('load', function(){

		$.knowhere.OuterResourcesLoaded();

	});

})(jQuery);