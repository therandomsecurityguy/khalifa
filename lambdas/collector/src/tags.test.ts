import { extractCommonProperties, type TagMap } from './tags';

describe('extractCommonProperties', () => {
  it('returns empty object when no tags provided', () => {
    expect(extractCommonProperties(undefined)).toEqual({});
    expect(extractCommonProperties({})).toEqual({});
  });

  it('extracts env from environment tag', () => {
    const tags: TagMap = { environment: 'production' };
    expect(extractCommonProperties(tags)).toEqual({ env: 'production' });
  });

  it('normalizes data_classification values', () => {
    const tags: TagMap = { 'data-classification': 'Restricted' };
    expect(extractCommonProperties(tags)).toEqual({ data_classification: 'restricted' });
  });

  it('converts crown_jewel string to boolean', () => {
    expect(extractCommonProperties({ crown_jewel: 'true' })).toEqual({ crown_jewel: true });
    expect(extractCommonProperties({ crown_jewel: 'yes' })).toEqual({ crown_jewel: true });
    expect(extractCommonProperties({ crown_jewel: 'false' })).toEqual({ crown_jewel: false });
    expect(extractCommonProperties({ crown_jewel: 'Production' })).toEqual({
      crown_jewel: false,
    });
  });

  it('extracts owner', () => {
    expect(extractCommonProperties({ owner: 'team-security' })).toEqual({
      owner: 'team-security',
    });
  });

  it('extracts business_unit', () => {
    expect(extractCommonProperties({ 'business-unit': 'retail' })).toEqual({
      business_unit: 'retail',
    });
  });

  it('combines multiple props from one tag set', () => {
    const tags: TagMap = {
      environment: 'prod',
      owner: 'platform',
      'data-classification': 'internal',
    };
    expect(extractCommonProperties(tags)).toEqual({
      env: 'prod',
      data_classification: 'internal',
      owner: 'platform',
    });
  });
});