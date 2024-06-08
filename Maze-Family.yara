import "console"

private rule Maze_Family{



	strings:
		
	$indicator = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

	condition:
		$indicator
}

rule Maze_Family_Network_Indicator{
	strings:
		$post = "POST /%s HTTP/1.1"

	condition:
		$post
}

rule Maze_Family_RansomName_Indicator{
	strings:
		$path = ".bmp"

	condition:
		$path
}

rule IS_NOT_SAME_FAMILY{
	condition:
		not Maze_Family  
		

}