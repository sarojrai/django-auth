/**
 * WTAudio
 * @version 1.0.0
 * Website http://www.wingart.net
 * @license The MIT License (MIT)
 */

;(function($, window, document){

	"use strict";

	/**
	 * Creates a player.
	 * @class The WTAudio.
	 * @public
	 * @param {HTMLElement|jQuery} element - The element to create the player for.
	 * @param {Object} [options] - The options
	 */
	function WTAudio(element, options){

		/**
		 * Current options set by the caller including defaults.
		 * @public
		 */
		this.options = $.extend({}, WTAudio.defaults, options);

		this.ISRTL = getComputedStyle(document.body).direction === "rtl";

		/**
		 * Plugin element.
		 * @public
		 */
		this.$element = $(element);



		this.AudioEl = this.$element.get(0);

		this.controls = {};

		this.setup();
		
	}

	/**
	 * Default options for the player.
	 * @public
	 */
	WTAudio.defaults = {

		controls: {
			playPause: true,
			currentTime: true,
			fullTime: true,
			muteButton: true,
			volumeBar: true
		},
		autoplay: false,
		loop: false

	}

	/**
	 * Setups the current settings.
	 * @public
	 */
	 WTAudio.prototype.setup = function(){

	 	this.generateMarkup();
	 	this.eventsCall();

	 }

	 /**
	 * Create HTML Markup for the player
	 * @public
	 */
	 WTAudio.prototype.generateMarkup = function(){

	 	var markup = [];

	 	var self = this;

	 	console.log(this.AudioEl);

	 	markup.push("<div class='wt_container'>");
	 
	 	if(this.options.controls.playPause){
	 		markup.push("<div class='wt_section' style='width: 28px;'><button class='wt_play_pause'></button></div>");
	 	}
	 	if(this.options.controls.currentTime){
			markup.push("<div class='wt_section' style='width: 31px;'><div class='wt_current_time'>00:00</div></div>");
	 	}

	 	markup.push("<div class='wt_section'><div class='wt_timebar'><div class='wt_indicator'></div></div></div>");

	 	if(this.options.controls.fullTime){
	 		markup.push("<div class='wt_section' style='width: 45px;'><div class='wt_full_time'>"+this.formattingTime(this.AudioEl.duration)+"</div></div>");
	 	}

	 	if(this.options.controls.muteButton){
	 		markup.push("<div class='wt_section' style='width: 25px;'><button class='wt_mute'></button></div>");
	 	}

	 	if(this.options.controls.volumeBar){
	 		markup.push("<div class='wt_section' style='width: 48px;'><div class='wt_volumebar'><div class='wt_indicator' style='width:" + this.AudioEl.volume * 100 + "%;'></div></div></div>")
	 	}

	 	markup.push("</div>");

	 	this.$element.before(markup.join(""));
	 	this.$element.hide();

	 	this.storeControls();

	}

	WTAudio.prototype.storeControls = function(){

		this.$container = this.$element.prev('.wt_container');

		this.controls.playPauseBtn = this.$container.find('.wt_play_pause');
		this.controls.muteBtn = this.$container.find('.wt_mute');
		this.controls.timeBar = this.$container.find('.wt_timebar');
		this.controls.currentTimeBar = this.$container.find('.wt_current_time');
		this.controls.timeBarIndicator = this.controls.timeBar.find('.wt_indicator');
		this.controls.volumeBar = this.$container.find('.wt_volumebar');
		this.controls.volumeBarIndicator = this.controls.volumeBar.find('.wt_indicator');

	}

	/**
	* Save internal event references and add event based functions.
	* @protected
	*/
	WTAudio.prototype.eventsCall = function(){
		
		if(this.options.controls.playPause){
			this.controls.playPauseBtn.on('click.play_pause', this.onPlayPause.bind(this));
		}
		if(this.options.controls.muteButton){
			this.controls.muteBtn.on('click.mute', this.onMute.bind(this));
		}
		if(this.options.controls.volumeBar){
			this.controls.volumeBar.on('click.volume', this.onChangeVolume.bind(this));
		}

		this.controls.timeBar.on('click.changecurrenttime', this.onChangeCurrentTime.bind(this));

	};

	/**
	* Handles the play/pause event.
	* @todo Simplify
	* @protected
	* @param {Event} event - The event arguments.
	*/
	WTAudio.prototype.onPlayPause = function(e){

		if(this.AudioEl.paused){
			this.AudioEl.play();
			this.fillCurrentTime();
			this.$container.addClass('playing');
		}
		else{
			this.AudioEl.pause();
			this.stopCurrentTime();
			this.$container.removeClass('playing');
		}

	}

	/**
	* Handles the mute event.
	* @todo Simplify
	* @protected
	* @param {Event} event - The event arguments.
	*/
	WTAudio.prototype.onMute = function(e){
		
		if(this.AudioEl.muted){

			this.AudioEl.muted = false;
			this.controls.muteBtn.removeClass('muted');
			this.controls.volumeBarIndicator.css('width', this.volumeState * 100 + '%');

		}
		else{

			this.volumeState = this.AudioEl.volume;
			this.controls.volumeBarIndicator.css('width','0%');

			this.AudioEl.muted = true;
			this.controls.muteBtn.addClass('muted');

		}

	}

	/**
	* Handles the change current time event.
	* @protected
	* @param {Event} event - The event arguments.
	*/
	WTAudio.prototype.onChangeCurrentTime = function(e){

		var ePosition = this.ISRTL ? 
				this.controls.timeBar.offset().left + this.controls.timeBar.outerWidth() - e.pageX :
				e.pageX - this.controls.timeBar.offset().left,
			tBWidth = this.controls.timeBar.outerWidth(),
			percent = ePosition / tBWidth * 100,
			resultTime = this.AudioEl.duration * percent / 100;

		this.AudioEl.currentTime = resultTime;
		this.fillCurrentTime();

	}

	/**
	* Handles the change volume event.
	* @protected
	* @param {Event} event - The event arguments.
	*/
	WTAudio.prototype.onChangeVolume = function(e){

		var ePosition = this.ISRTL ? 
				this.controls.volumeBar.offset().left + this.controls.volumeBar.outerWidth() - e.pageX :
				e.pageX - this.controls.volumeBar.offset().left,
			vBWidth = this.controls.volumeBar.outerWidth(),
			percent = ePosition / vBWidth * 100;

		this.AudioEl.volume = percent / 100;
		this.controls.volumeBarIndicator.css('width', percent + '%');

	}

	/**
	* Formatting current time for the timebar
	* @protected
	* @param Number seconds - the current time of audi track in seconds.
	*/
	WTAudio.prototype.formattingTime = function(seconds){

		var fMinutes = new Number(0),
			fSeconds = new Number(0);

		if(seconds > 60){
			fMinutes = Math.floor(seconds / 60);
			fSeconds = Math.floor(seconds % 60);
		}
		else fSeconds = Math.floor(seconds);

		if(fMinutes < 10) return "0" + fMinutes.toString() + ":" + (fSeconds < 10 ? "0" + fSeconds.toString() : fSeconds);

		return fMinutes.toString() + ":" + (fSeconds < 10 ? "0" + fSeconds.toString() : fSeconds);

	}


	/**
	* Calculates current time for the timebar
	* @protected
	*/
	WTAudio.prototype.fillCurrentTime = function(){

		var self = this,
			elWidth = self.controls.timeBar.outerWidth(),
			percent;

		self.currentTimeInterval = setInterval(function(){

			percent = self.AudioEl.currentTime / self.AudioEl.duration * 100;

			self.controls.currentTimeBar.text(self.formattingTime(self.AudioEl.currentTime));
			self.controls.timeBarIndicator.css('width', percent + '%');

			if(self.AudioEl.ended && !self.options.loop){
				self.controls.currentTimeBar.text("00:00");
				self.controls.timeBarIndicator.css('width', '0%');
				self.$container.removeClass('playing');
			}

		},10);

	}


	/**
	* Stop calculates current time for the timebar
	* @protected
	*/
	WTAudio.prototype.stopCurrentTime = function(){

		if(this.currentTimeInterval) clearInterval(this.currentTimeInterval);

	}

	/**
	 * The jQuery Plugin for the WTAudio Player
	 * @public
	 */
	$.fn.WTAudio = function(options){

		return this.each(function(){

			if(!$(this).data('WTAudio')){
				$(this).data('WTAudio', new WTAudio(this, options));
			}

		});

	}

})(window.jQuery, window, document);