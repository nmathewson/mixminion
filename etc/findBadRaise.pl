#!/usr/bin/perl -w

unshift (@ARGV, '-') unless @ARGV;

for $fname (@ARGV) {
    open FH, $fname or die $!;

    $more = 0;
    while (<FH>) {
	if ($more) {
	    chomp $line;
	    $line .= $_;
	} else {
	    $line = $_;
	}
	$more = 0;
	if (/raise *\w+\(\'(?:[^\\\']+|\\.)*\' *(.*)/ or
	    /raise *\w+\(\"(?:[^\\\"]+|\\.)*\" *(.*)/) {
	    $rest = $1;
	    next if ($rest =~ /^[%\)]/);
	    if ($rest =~ /^ *$/) {
		$more = 1; next;
	    }
	    $bad = 0;
	    if ($rest =~ /^,/) { $bad = 1; }
	} else {
	    next;
	}
	if ($bad) {
	    print "##$fname:$.:$line";
	} else {
	    print "  $fname:$.:$line";
	}
    }
    close FH;
}
