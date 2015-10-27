use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::BUILDARGS;

# ABSTRACT: BUILDARGS role for Resource Identifiers as per RFC3986 and RFC3987

# VERSION

# AUTHORITY

use Carp qw/croak/;
use Class::Method::Modifiers qw/install_modifier/;
use Encode qw/decode/;
use MarpaX::Role::Parameterized::ResourceIdentifier::Types -all;
use Moo::Role;
use MooX::Role::Parameterized;
use Type::Params qw/compile/;
use Types::Standard -all;
use Types::TypeTiny qw/StringLike/;
use Types::Encodings qw/Bytes/;

#
# The "new" signature is common between all implementations:
# _top    is  (StringLike|HashRef, Maybe[SchemeLike|AbsoluteReference|StringifiedAbsoluteReference])
# _others are (StringLike|HashRef, Maybe[Str])
#

my $check_top    = compile(StringLike|HashRef, Maybe[SchemeLike|AbsoluteReference|StringifiedAbsoluteReference]);
my $check_others = compile(StringLike|HashRef, Maybe[Str]);

role {
  my $params = shift;

  # -----------------------
  # Sanity checks on params
  # -----------------------
  my %PARAMS = ();
  map { $PARAMS{$_} = $params->{$_} } qw/whoami type bnf_package normalizer/;
  #
  # We will not insert methods in the role but in the calling package
  #
  croak 'whoami must exist and do Str' unless Str->check($PARAMS{whoami});
  my $whoami = $PARAMS{whoami};
  #
  # And this depend on its type: Top of NotTop
  #
  croak 'type must exist and do Enum[qw/Top NotTop/]' unless defined($PARAMS{type}) && grep {$_ eq $PARAMS{type}} qw/Top NotTop/;
  my $type = $PARAMS{type};
  #
  # We require a name for the second argument
  #
  croak "[$type] second_argument must exist and do Str" unless Str->check($params->{second_argument});
  my $second_argument = $params->{second_argument};

  my $check = $type eq 'Top' ? $check_top : $check_others;
  print STDERR "INSTALLING BUILDARGS in $whoami\n";
  install_modifier($whoami, 'fresh', BUILDARGS => sub {
                     my $class = shift;

                     my ($first, $second) = $check->($_[0], $_[1]);
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
                     $args->{$second_argument} = $second if (! Undef->check($second));
                     $args
                   }
                  );
};

1;
