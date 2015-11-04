use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::BUILDARGS;

# ABSTRACT: Resource Identifier : BUILDARGS role

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Exporter qw/import/;
use Encode 2.21 qw/find_encoding decode/; # 2.21 for mime_name support
use MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Moo::Role;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;
#
# This is for non-Moo packages, i.e. _top
#
our @EXPORT_OK = qw/BUILDARGS/;

our $setup         = MarpaX::Role::Parameterized::ResourceIdentifier::Setup->new;
our $check         = compile(StringLike|HashRef, Maybe[Str]);
our @ucs_mime_name = map { find_encoding($_)->mime_name } qw/UTF-8 UTF-16 UTF-16BE UTF-16LE UTF-32 UTF-32BE UTF-32LE/;

sub BUILDARGS {
  my $class = shift;
  my ($first, $scheme) = $check->($_[0], $_[1]);
  #
  # If first is a HashRef ref, it must have at least two keys pushed into decode():
  # - octets          Bytes (bytes)
  # - encoding        Str (encoding)
  # - decode_strategy Maybe[Int] (decode option)
  # or
  # - input
  # where input have precedence
  #
  # It may also have:
  # - idn
  # - nfc
  # - ... whatever - it is kepts as it
  #
  my $input;
  my %rest = ();
  if (HashRef->check($first)) {
    if (exists($first->{input})) {
      croak 'input must do StringLike' unless StringLike->check($first->{input});
      my $thisinput = delete($first->{input});
      $input = "$thisinput";   # Eventual stringification
    } else {
      croak 'octets must do Bytes' unless Bytes->check($first->{octets});
      croak 'encoding must do Str' unless Str->check($first->{encoding});
      #
      # octets, encoding and decode_strategy are kept. encoding in particular
      # will be used in the IRI case for as_uri
      #
      my $octets          = $first->{octets};
      my $encoding        = $first->{encoding};
      #
      # Force is_character_normalized if we are converting from a non-UCS-based
      # character encoding
      #
      my $enc_mime_name = find_encoding($encoding)->mime_name;
      my $is_character_normalized = grep { $enc_mime_name eq $_ } @ucs_mime_name;
      $first->{is_character_normalized} = $is_character_normalized if ! $is_character_normalized;
      #
      # Encode::encode will croak by itself if decode_strategy is not ok
      #
      my $decode_strategy = $first->{decode_strategy} // Encode::FB_CROAK;
      $input = decode($encoding, $octets, $decode_strategy);
    }
    %rest = %{$first};
  } else {
    $input = "$first";  # Eventual stringification
  }
  if ($setup->uri_compat) {
    #
    # Copy from URI:
    # Get rid of potential wrapping
    #
    $input =~ s/^<(?:URL:)?(.*)>$/$1/;
    $input =~ s/^"(.*)"$/$1/;
    $input =~ s/^\s+//;
    $input =~ s/\s+$//;
  }
  my $args = { input => $input, %rest };
  $args->{scheme} = lc($scheme) if ! Undef->check($scheme);

  $args
}

1;
