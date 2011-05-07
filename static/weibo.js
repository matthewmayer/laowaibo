$(document).ready(function() { 
    //highlight current link
	$("nav").currant();

	//relative times
	$("abbr.timeago").timeago();

    //autotranslate
	var prev;
	setInterval(function(){
		var orig = $('#tweetzh').val();
		if (orig!=prev) {
			prev = orig;
			$('#tweeten').load("/translate",{text:prev,lang:'zh-Hans|en'});
		}
	},2000);
	
	//press down to manually translate
	$('#tweetzh').bind('keydown', 'down', function() {
		var range = $('#tweetzh').getSelection();
		var t = $('#tweetzh').val();
		$.post("/translate",{text:range.text,lang:'en|zh-Hans'},function(res) {
			var newtxt = t.substr(0, range.start)+res+(t.substr(range.end, t.length));
			$('#tweetzh').val(newtxt);
		})	
		return false;
	});
	
	//follow
	$("a.follow").click(function(e){  
		//prevent default action  
		e.preventDefault();  

		//define the target and get content then load it to container  
		var self = $(this);
		var url = $(this).attr("href");  
		$.ajax({
          url: url,
          success: function(data) {
              if (data.status=="ok") {
                  self.parent().html("Followed!")
              } else {
                  alert(data.message);
              }
          },
          dataType: 'json'
        }); 
	});
	
});