(function(d){d.fn.formset=function(c){var a=d.extend({},d.fn.formset.defaults,c),p=a.extraClasses.join(" "),j=d("#id_"+a.prefix+"-TOTAL_FORMS"),h=d("#id_"+a.prefix+"-MAX_NUM_FORMS"),c=d(this),k=function(i,e){a.extraClasses&&(i.removeClass(p),i.addClass(a.extraClasses[e%a.extraClasses.length]))},l=function(a,e,d){var b=RegExp(e+"-(\\d+|__prefix__)-"),e=e+"-"+d+"-";a.attr("for")&&a.attr("for",a.attr("for").replace(b,e));a.attr("id")&&a.attr("id",a.attr("id").replace(b,e));a.attr("name")&&a.attr("name",
a.attr("name").replace(b,e))},m=function(){return h.length==0||h.val()==""||h.val()-j.val()>0},n=function(b){b.is("TR")?b.children(":last").append('<a class="'+a.deleteCssClass+'" href="javascript:void(0)">'+a.deleteText+"</a>"):b.is("UL")||b.is("OL")?b.append('<li><a class="'+a.deleteCssClass+'" href="javascript:void(0)">'+a.deleteText+"</a></li>"):b.append('<a class="'+a.deleteCssClass+'" href="javascript:void(0)">'+a.deleteText+"</a>");b.find("a."+a.deleteCssClass).click(function(){var b=d(this).parents("."+
a.formCssClass),f=b.find('input:hidden[id $= "-DELETE"]'),i=b.siblings("a."+a.addCssClass+", ."+a.formCssClass+"-add"),c;f.length?(f.val("on"),b.hide(),c=d("."+a.formCssClass).not(":hidden")):(b.remove(),c=d("."+a.formCssClass).not(".formset-custom-template"),j.val(c.length));for(var g=0,h=c.length;g<h;g++)k(c.eq(g),g),f.length||c.eq(g).find("input,select,textarea,label,div").each(function(){l(d(this),a.prefix,g)});i.is(":hidden")&&m()&&i.show();a.removed&&a.removed(b);return!1})};c.each(function(b){var e=
d(this),c=e.find('input:checkbox[id $= "-DELETE"]');c.length&&(c.is(":checked")?(c.before('<input type="hidden" name="'+c.attr("name")+'" id="'+c.attr("id")+'" value="on" />'),e.hide()):c.before('<input type="hidden" name="'+c.attr("name")+'" id="'+c.attr("id")+'" />'),d('label[for="'+c.attr("id")+'"]').hide(),c.remove());e.find("input,select,textarea,label,div").length>0&&(e.addClass(a.formCssClass),e.is(":visible")&&(n(e),k(e,b)))});if(c.length){var o=!m(),b;a.formTemplate?(b=a.formTemplate instanceof
d?a.formTemplate:d(a.formTemplate),b.removeAttr("id").addClass(a.formCssClass+" formset-custom-template"),b.find("input,select,textarea,label,div").each(function(){l(d(this),a.prefix,"__prefix__")}),n(b)):(b=d("."+a.formCssClass+":last").clone(!0).removeAttr("id"),b.find('input:hidden[id $= "-DELETE"]').remove(),b.find("input,select,textarea,label,div").not(a.keepFieldValues).each(function(){var a=d(this);a.is("input:checkbox")||a.is("input:radio")?a.attr("checked",!1):a.val("")}));a.formTemplate=
b;c.attr("tagName")=="TR"?(b=c.eq(0).children().length,b=d('<tr><td colspan="'+b+'"><a class="'+a.addCssClass+'" href="javascript:void(0)">'+a.addText+"</a></tr>").addClass(a.formCssClass+"-add"),c.parent().append(b),o&&b.hide(),b=b.find("a")):(c.filter(":last").after('<a class="'+a.addCssClass+'" href="javascript:void(0)">'+a.addText+"</a>"),b=c.filter(":last").next(),o&&b.hide());b.click(function(){var b=parseInt(j.val()),c=a.formTemplate.clone(!0).removeClass("formset-custom-template"),f=d(d(this).parents("tr."+
a.formCssClass+"-add").get(0)||this);k(c,b);c.insertBefore(f).show();c.find("input,select,textarea,label,div").each(function(){l(d(this),a.prefix,b)});j.val(b+1);m()||f.hide();a.added&&a.added(c);return!1})}return c};d.fn.formset.defaults={prefix:"form",formTemplate:null,addText:"add another",deleteText:"remove",addCssClass:"add-row",deleteCssClass:"delete-row",formCssClass:"dynamic-form",extraClasses:[],keepFieldValues:"",added:null,removed:null}})(jQuery);