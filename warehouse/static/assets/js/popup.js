//loading popup with jQuery magic!
var popupStatus = 0;
function loadPopup(){
        //loads popup only if it is disabled
        if(popupStatus==0){
                $("#backgroundPopup").css({
                        "opacity": "0.7"
                });
		$('#backgroundPop').addClass('myclass');
                $("#backgroundPopup").fadeIn("slow");
                $("#popupContact").fadeIn("slow");
                popupStatus = 1;
        }
        $("#popupform").hide();
}

//disabling popup with jQuery magic!
function disablePopup(){
    
        //disables popup only if it is enabled
        if(popupStatus==1){
		$('#backgroundPop').removeClass('myclass');
                $("#backgroundPopup").fadeOut("slow");
                $("#popupContact").fadeOut("slow");
                popupStatus = 0;
        }
}


function centerPopupModifyOrder(order_id){

        $("#popupContact").css({
                "position": "absolute",
                "top": 122,
                "left": 204,
                "width":904,
                "height":400,
                "padding":0,


        });
	 $("#backgroundPopup").css({
                });
	$("#popupContact").load("/dispatch/get_order/"+order_id+"/")
}



function centerPopupInscanSKU(cartoon_id){

        $("#popupContact").css({
                "position": "absolute",
                "top": 122,
                "left": 204,
                "width":904,
                "height":400,
                "padding":0,


        });
         $("#backgroundPopup").css({
                });
        $("#popupContact").load("/reception/scanned_sku/"+cartoon_id+"/")
}


$(document).ready(function(){
        $(".include_shipment_outscan").on("click",function(){
            var order_id =$(this).attr("order_id");
                //alert(order_id);
	
                centerPopupModifyOrder(order_id);
                loadPopup();
        });
});


$(document).ready(function(){
        $(".include_sku1").on("click",function(){
            var cartoon_id =$(this).attr("cartoon_id");
                //alert(order_id);
                centerPopupInscanSKU(cartoon_id);
                loadPopup();
        });
});

