use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS;

# ABSTRACT: BUILDARGS role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Encode qw/decode/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Moo::Role;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;

#
# The "new" signature is common between all implementations, so is BUILDARGS
#

my $check = compile(StringLike|HashRef, Maybe[SchemeLike|AbsoluteReference|StringifiedAbsoluteReference]);

sub BUILDARGS {
  my $class = shift;

  my ($first, $scheme) = $check->($_[0], $_[1]);
  #
  # If first is a HashRef ref, it must have at least two keys pushed into decode():
  # - octets          Bytes (bytes)
  # - encoding        Str (encoding)
  # - decode_strategy Maybe[Int] (decode option)
  # It may also have:
  # - idn
  # - nfc
  # - ... whatever - it is kepts as it
  #
  my $input;
  my %rest = ();
  if (HashRef->check($first)) {
    croak 'octets must do Bytes' unless Bytes->check($first->{octets});
    croak 'encoding must do Str' unless Str->check($first->{encoding});

    my $octets          = delete($first->{octets});
    my $encoding        = delete($first->{encoding});

    #
    # Encode::encode will croak by itself if decode_strategy is not ok
    #
    my $decode_strategy = delete($first->{decode_strategy}) // Encode::FB_CROAK;
    %rest = %{$first};

    $input = decode($encoding, $octets, $decode_strategy);
  } else {
    $input = "$first";  # Eventual stringification
  }
  #
  # Copy from URI:
  # Get rid of potential wrapping
  #
  $input =~ s/^<(?:URL:)?(.*)>$/$1/;
  $input =~ s/^"(.*)"$/$1/;
  $input =~ s/^\s+//;
  $input =~ s/\s+$//;
  my $args = { input => $input, %rest };
  $args->{scheme} = $scheme if (! Undef->check($scheme));

  $args
}

1;
