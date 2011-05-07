/*
 * currant: a jQuery plugin
 * @requires jQuery v1.2.3 or later
 *
 * removes the "a" tag on any a elements within the given element if
 * the href of the link is the current page
 * 
 */
(function($) {
 
  $.fn.currant = function() {
    var self = this;
    self.each(currantify);
    return self;
  };

  function currantify() {
    $(this).find("a").each(checkify);
  }
  function checkify() {
      if($(this).attr("href")==(document.location.pathname+document.location.search)) {
          $(this).parent().addClass("current");
      }
  }

}(jQuery));
