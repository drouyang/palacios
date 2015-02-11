#!/usr/bin/perl


open(FILE, $ARGV[0]);



%mallocs;


while ($line = <FILE>) {
  chomp $line;

  if ($line =~ /.*V3_MALLOC: addr=(.*)/) {
   # print "MALLOC at $1\n";
    if (!$mallocs{$1}) {
      $mallocs{$1} = 1;
    } else {
      $mallocs{$1} += 1;
    }

  } elsif ($line =~ /.*V3_FREE: addr=(.*)/) {
  #  print "FREE at $1\n";
    if (!$mallocs{$1}) {
      print "ERROR: FREEING ADDRESS that wasn't malloced\n";
    } elsif ($mallocs{$1} == 2) {
      print "ERROR: Freeing address that was already freed\n";
    } else {
      $mallocs{$1} -= 1;
    }
  }
}



foreach $key (keys %mallocs) {
  if ($mallocs{$key} > 0) {
    print "ERROR: MEMORY LEAK at $key\n";
  }
}
close(FILE);
