use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role;

# ABSTRACT: Internationalized Resource Identifier (IRI) : top role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Module::Runtime qw/use_module/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode qw/decode/;
use Moo::Role;
use MooX::Role::Parameterized;
use Try::Tiny;
use Types::Standard -all;
use Types::Encodings qw/Bytes/;

role {
  my $params = shift;

  croak "package must exist and do Str" unless exists($params->{package}) && Str->check($params->{package});
  my $package  = $params->{package};

  #
  # Writen like this because we want to control the class
  #
  # Pre-load _common and _generic implementations, that must exist
  #
  use_module(join('::', $package, '_common'));
  use_module(join('::', $package, '_generic'));

  my $around_new = sub {
    my ($orig, $class) = (shift, shift);

    my $input = '';

    if (@_) {
      $input = shift;
      #
      # More than one argument is supported only in the top package
      #
      croak 'Only one argument is supported' if (($#_ != 0) && ($class ne $package));
      #
      # ArrayRef as first argument is supported only in the top package
      #
      if (($class eq $package) && ArrayRef->check($input)) {
        croak 'Referenced array must have a least two elements'   if ($#{$input} < 1);

        my $encoding = shift(@{$input});
        croak 'Referenced array must have a string in first element' if (! Str->check($encoding));

        my $bytes = shift(@{$input});
        croak 'Referenced array must have bytes in second element' if (! Bytes->check($bytes));

        $input = decode($encoding, $bytes, @{$input});
      } else {
        $input = "$input"; # Stringification in any case
      }
    }

    my $new;
    #
    # Extra check that should never be false, because this role is only included by
    # RFCXXXX.pm - but who knows: we want to affect only the new of the class in which
    # we are injected
    #
    if ($class eq $package) {
      #
      # Copy from URI:
      # Get rid of potential wrapping
      #
      $input =~ s/^<(?:URL:)?(.*)>$/$1/;
      $input =~ s/^"(.*)"$/$1/;
      $input =~ s/^\s+//;
      $input =~ s/\s+$//;
      #
      # Specific: may fail, or even not exist
      #
      if ($input =~ /^[A-Za-z][A-Za-z0-9+.-]*(?=:)/p) {
        try {
          my $class = sprintf('%s::%s', $package, ${^MATCH});
          use_module($class);
          $new = $class->new($input);
        }
      }
      #
      # else _generic: may fail
      #
      try {
        my $class = sprintf('%s::%s', $package, '_generic');
        $new = $class->new($input);
      } if (! $new);
      #
      # fallback _common : must succeed
      #
      if (! $new) {
        my $class = sprintf('%s::%s', $package, '_common');
        $new = $class->new($input);
      }
      #
      # scheme argument
      #
      if (@_) {
        my $scheme = shift;
        if (! $new->can('is_relative')) {
          warn 'scheme argument ignored: implementation cannot tell if input is relative';
        } else {
          if ($new->is_relative) {
          }
        }
      }
    } else {
      $new = $class->$orig(@_);
    }

    $new
  };

  install_modifier($package, 'around', 'new', $around_new);

  method clone => sub { $package->new($_[0]->input) };

};

requires 'new';
requires 'clone';

1;
