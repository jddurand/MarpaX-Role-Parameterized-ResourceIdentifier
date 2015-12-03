use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::_common;

# ABSTRACT: Resource Identifier: Common syntax semantics

# VERSION

# AUTHORITY

use Moo::Role;
use Unicode::Normalize qw/normalize/;

sub can_scheme { my ($class, $scheme) = @_; $scheme =~ /\A[A-Za-z][A-Za-z0-9\+\-\.]*\z/ }

#
# Arguments of every callback:
# my ($self, $field, $value, $lhs) = @_;
#
around build_character_normalizer => sub {
  my ($orig, $self) = (shift, shift);

  my $rc = $self->$orig(@_);
  #
  # --------------------------------------------
  # http://tools.ietf.org/html/rfc3987
  # --------------------------------------------
  #
  # 5.3.2.2.  Character Normalization
  #
  # [The exceptions are] conversion
  # from a non-digital form, and conversion from a non-UCS-based
  # character encoding to a UCS-based character encoding. In these cases,
  # NFC or a normalizing transcoder using NFC MUST be used for
  # interoperability.
  #
  $rc->{''} = sub { normalize('NFC',  $_[2]) } if (! $self->is_character_normalized);
  $rc
};

1;
