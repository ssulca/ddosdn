#!/usr/bin/perl
use strict;
use CGI ':standard';
# La funcion Open3 de la libreria IPC permite el manejo de pipes
use IPC::Open3;

print header,
      start_html('web terminal');

local (*IN,*OUT);

my $pid = open3(\*IN, \*OUT ,0,'./fibo');
my $out = '';
my $cmd ;

print h1("fibo de 0 a 40");
#$cmd = 'sleep 10'; # toma el comando enviado en el formulario
#print IN "sleep 10\n"; # comand to bash
#print IN "date\n"; # comand to bash
#print IN "exit\n"; # close bash

# leer pipe
$out = do{local $/;<OUT>};

close BO; # cierra pipes
close BI;
waitpid($pid,0);

$out =~ s/\n/<br>/g; # convierte "\n" en "<br>"

# formulario
print start_form;
print h2("Comando");
#print textarea(-name=>'cmd',-id=>'cmd');
#print submit('Áction','send');
print end_form;
print h2("Salida");
print p("$out"); # imprime salida del bash

print end_html;

