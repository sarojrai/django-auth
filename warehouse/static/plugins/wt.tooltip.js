/**
 * WT Tooltip jQuery plugin.
 * @author WingArt Team
 * @version 1.0
 */
;(function($){
	'use strict';

	/**
	 * 
	 * 
	 * @var 
	 */
	var _positions = {
		top: {
			'position': 'absolute',
			'bottom': '100%',
			'left': '50%'
		},
		bottom: {
			'position': 'absolute',
			'top': '100%',
			'left': '50%'
		},
		right: {
			'position': 'absolute',
			'left': '100%',
			'top': '50%'
		},
		left: {
			'position': 'absolute',
			'right': '100%',
			'top': '50%'
		}
	},

	/**
	 * 
	 * 
	 * @var 
	 */
	_baseConfig = {
		cssPrefix: '',
		rtl: false,
		debounce: 5
	};

	/**
	 * 
	 * 
	 * @param 
	 *
	 * @return 
	 */
	function makeTooltip(position, text, className, width) {
		var tooltip = $('<span></span>', {
			text: text,
			class: (className ? className : 'tooltip') + ' animated'
		})
		.css(position && _positions[position] ? _positions[position] : _positions['top']);

		if(width) tooltip.css('width', width);

		tooltip.css('visibility', 'hidden');

		return tooltip;
	}

	/**
	 * 
	 * 
	 * @param 
	 *
	 * @return 
	 */
	function correctPosition(element, position) {

		if(!position || position == 'top' || position == 'bottom') {
			element.css('margin-left', element.outerWidth() / -2);
		}

		if(position == 'right' || position == 'left') {
			element.css('margin-top', element.outerHeight() / -2);
		}

	}

	/**
	 * Constructor Function.
	 * 
	 * @param jQuery $element
	 * @param Object options
	 *
	 * @return undefined
	 */
	function Tooltip($element, options){
		this.element = $element;
		this.config = $.extend({}, _baseConfig, options);

		// define helper descriptors
		Object.defineProperties(this, {
			tooltipClass : {
				get: function() {
					return this.config.cssPrefix + 'tooltip';
				}
			},
			cssTooltipClass: {
				get: function() {
					return '.' + this.config.cssPrefix + 'tooltip';
				}
			}
		});

		// defines handlers
		Object.defineProperties(this, {
			mouseEntered: {
				value: function(event) {
					var $this = $(this).css('position', 'relative'),
						self = event.data.self,
						tooltip,
						position = $this.data('tooltip-position') ? $this.data('tooltip-position') : 'top';
					if($this.find(self.cssTooltipClass).length) return false;

					tooltip = makeTooltip(
						position,
						$this.data('tooltip'),
						self.tooltipClass,
						self.config.width
					);

					$this.append(tooltip.addClass(position));

					correctPosition(tooltip, $this.data('tooltip-position'));

					if($this.data('timeoutId')) clearTimeout($this.data('timeoutId'));
					$this.data('timeoutId', setTimeout(function() {
						tooltip.css('visibility', 'visible').addClass(self.config.animateIn);
					}, self.config.debounce));
					
				},
				configurable: false,
				enumerable: false,
				writable: false
			},
			mouseLeft: {
				value: function(event) {
					var $this = $(this),
						self = event.data.self,
						tooltip = $this.find(self.cssTooltipClass);

					if(!tooltip.length) return;

					if(tooltip.hasClass(self.config.animateIn)) {
						tooltip.removeClass(self.config.animateIn).addClass(self.config.animateOut);
					}

					tooltip.on('webkitAnimationEnd mozAnimationEnd MSAnimationEnd oanimationend animationend', function(){
						$(this).remove();
					});

				},
				configurable: false,
				enumerable: false,
				writable: false
			}
		});

		this.init();
	}

	/**
	 * Initialization.
	 * 
	 * @return undefined
	 */
	Tooltip.prototype.init = function(){

		this.element.on('mouseenter', { self: this }, this.mouseEntered);
		this.element.on('mouseleave', { self: this }, this.mouseLeft);

	}

	$.fn.wtTooltip = function(options) {
		return this.each(function(i, el){
			var $this = $(el);
			if(!$this.data('wtTooltip')) {
				$this.data('wtTooltip', new Tooltip($this, options));
			}
		});
	}

})(jQuery);