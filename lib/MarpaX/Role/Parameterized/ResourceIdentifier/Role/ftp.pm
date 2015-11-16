use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Role::ftp;

# ABSTRACT: Resource Identifier: Generic/ftp syntax semantics role

# VERSION

# AUTHORITY

use Carp qw /croak/;
use Moo::Role;

sub can_scheme { my ($class, $normalized_scheme) = @_; $normalized_scheme eq 'ftp' }

around parse => sub {
  my ($orig, $self) = (shift, shift);
  my @rc = $self->$orig(@_);
  my $normalized_scheme = $self->normalized_scheme;
  croak 'scheme must be undef or ftp' unless ! defined($normalized_scheme) || $normalized_scheme eq 'ftp';
  @rc
};

1;
